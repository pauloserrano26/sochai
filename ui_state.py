"""
Persistência do estado da dashboard entre arranques.

O ``st.session_state`` do Streamlit só vive enquanto o processo do servidor
vive: ao fechar a janela do Streamlit perde-se a tab onde se estava, os filtros
escolhidos e — o que custa mais — o resultado do último cenário, que pode ter
levado dois minutos a gerar.

Este módulo grava esse estado em ``.state/ui_<conta>.json`` e repõe-o no
arranque seguinte. Duas decisões de desenho que valem uma nota:

* **A gravação é explícita** (botão "Guardar estado" na sidebar), nunca
  automática — o snapshot é sempre um ponto que o utilizador escolheu, e não
  o que a sessão tinha no instante em que morreu.
* **Um ficheiro por conta autenticada.** O admin e cada colaborador
  reencontram a sua própria vista; nenhum vê os filtros ou resultados de outro.
* **A sessão autenticada nunca é gravada.** O ficheiro só é lido depois do
  login, portanto reabrir a dashboard continua a exigir credenciais — o
  snapshot não é uma porta de entrada.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime
from typing import Any, Optional, Sequence

import streamlit as st

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".state")
_VERSION = 1

# Chaves internas do session_state usadas por este módulo.
_RESTORED = "_ui_state_restored"          # restore() já correu nesta sessão
_CAME_FROM_DISK = "_ui_state_came_from_disk"  # ...e trouxe estado de volta
_SAVED_AT = "_ui_state_saved_at"
_FROM_DISK = "_ui_state_from_disk"


# A tab ativa precisa de duas chaves, não de uma. O ``st.tabs`` só expõe a tab
# em ``session_state["main_tab"]`` depois de as tabs serem criadas — e a sidebar,
# onde vive o botão de gravar, é desenhada antes disso, pelo que nesse momento a
# chave do widget ainda não existe. O dashboard copia-a para ``_active_tab``
# (chave simples, não de widget) logo após criar as tabs; como essas chaves
# sobrevivem entre reruns, no clique seguinte já tem a tab correta.
TAB_WIDGET_KEY = "main_tab"
ACTIVE_TAB_KEY = "_active_tab"


# Widgets cujas opções são literais fixas no dashboard.py — repor o valor
# gravado é sempre seguro.
WIDGET_KEYS: tuple[str, ...] = (
    ACTIVE_TAB_KEY,         # tab de topo ativa
    "inc_filter",           # Operations — filtro de estado dos incidentes
    "asset_dept",           # Ativos — filtros da lista
    "asset_crit",
    "asset_type_f",
    "diff_filter",          # Gamificação — dificuldade das missões
    "asset_scn_max",        # Cenários — parâmetros do gerador a partir de ativos
    "asset_scn_per_asset",
    "asset_scn_genpb",
    "asset_scn_phish",
    "res_show_sim",         # Resultados — mostrar simulações sintéticas
)

# Widgets cujas opções vêm da API. O valor é gravado, mas é validado contra as
# opções vivas antes de o widget ser criado (ver ``keep_valid``) — uma opção que
# tenha desaparecido entre arranques ficaria senão a ser regravada para sempre.
VALIDATED_KEYS: tuple[str, ...] = (
    "scn_catalog_sel",      # Cenários — cenário do catálogo selecionado
    "asset_scn_assets",     # Cenários — ativos incluídos
)

# Resultados de execuções que o utilizador disparou explicitamente e que custam
# minutos a regenerar. Não são dados vivos do SOC — são o registo de uma
# execução passada, por isso a UI mostra-os com a data do snapshot.
RESULT_KEYS: tuple[str, ...] = (
    "last_scenario_result",
    "asset_scenario_result",
    "_sim_logs",
)

_ALL_WIDGETS = WIDGET_KEYS + VALIDATED_KEYS


# ------------------------------------------------------------------ #
# Ficheiro
# ------------------------------------------------------------------ #

def _slug(username: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", (username or "").strip()) or "anon"


def path_for(username: str) -> str:
    return os.path.join(_DIR, f"ui_{_slug(username)}.json")


def _jsonable(value: Any) -> bool:
    try:
        json.dump(value, _Sink())
    except (TypeError, ValueError):
        return False
    return True


class _Sink:
    """Destino descartável — serializa para validar, sem construir a string."""

    def write(self, _chunk: str) -> None:  # pragma: no cover - trivial
        pass


# ------------------------------------------------------------------ #
# API pública
# ------------------------------------------------------------------ #

def save(username: str) -> str:
    """Grava o estado atual da sessão. Devolve o caminho do ficheiro escrito."""
    widgets = {
        key: st.session_state[key]
        for key in _ALL_WIDGETS
        if key in st.session_state and _jsonable(st.session_state[key])
    }
    results = {
        key: st.session_state[key]
        for key in RESULT_KEYS
        if st.session_state.get(key) is not None and _jsonable(st.session_state[key])
    }

    saved_at = datetime.now().isoformat(timespec="seconds")
    payload = {
        "version": _VERSION,
        "username": username,
        "saved_at": saved_at,
        "widgets": widgets,
        "results": results,
    }

    os.makedirs(_DIR, exist_ok=True)
    target = path_for(username)
    tmp = f"{target}.tmp"
    # Escrita atómica: um Ctrl+C a meio da gravação não deixa um snapshot
    # truncado que rebentaria no arranque seguinte.
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, target)

    st.session_state[_SAVED_AT] = saved_at
    # O que está em memória passou a ser o snapshot — já não é "vindo do disco".
    st.session_state[_FROM_DISK] = {}
    st.session_state[_CAME_FROM_DISK] = False
    return target


def restore(username: str) -> Optional[str]:
    """
    Repõe o estado gravado, uma única vez por sessão. Devolve o instante em que
    o snapshot foi gravado, ou ``None`` se não havia nada para repor.

    Só escreve chaves que ainda não existam no ``session_state``, para que uma
    escolha feita nesta sessão nunca seja sobreposta pelo snapshot.
    """
    if st.session_state.get(_RESTORED):
        return st.session_state.get(_SAVED_AT)
    st.session_state[_RESTORED] = True

    try:
        with open(path_for(username), encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        # Snapshot ilegível — arrancar limpo é melhor que falhar o arranque.
        return None

    if payload.get("version") != _VERSION or payload.get("username") != username:
        return None

    saved_at = payload.get("saved_at")

    for key, value in (payload.get("widgets") or {}).items():
        if key in _ALL_WIDGETS and key not in st.session_state:
            st.session_state[key] = value

    # Semeia a chave do widget das tabs a partir da tab gravada, para que o
    # st.tabs abra onde o utilizador estava.
    tab = st.session_state.get(ACTIVE_TAB_KEY)
    if tab is not None and TAB_WIDGET_KEY not in st.session_state:
        st.session_state[TAB_WIDGET_KEY] = tab

    from_disk = {}
    for key, value in (payload.get("results") or {}).items():
        if key in RESULT_KEYS and key not in st.session_state:
            st.session_state[key] = value
            from_disk[key] = saved_at

    st.session_state[_SAVED_AT] = saved_at
    st.session_state[_FROM_DISK] = from_disk
    st.session_state[_CAME_FROM_DISK] = True
    return saved_at


def was_restored() -> bool:
    """
    True se esta sessão arrancou a partir de um snapshot e ainda não o regravou.
    A sidebar usa isto para dizer "vista reposta" em vez de "estado gravado".
    """
    return bool(st.session_state.get(_CAME_FROM_DISK))


def keep_valid(key: str, options: Sequence) -> None:
    """
    Descarta do estado reposto os valores que já não existem nas opções vivas do
    widget ``key``. Chamar imediatamente antes de criar o widget.

    O Streamlit já ignora um valor inválido (cai na primeira opção, ou em lista
    vazia), mas deixa-o no ``session_state`` — onde seria apanhado pelo próximo
    "Guardar estado" e arrastado de snapshot em snapshot. Isto limpa-o.
    """
    if key not in st.session_state:
        return
    value = st.session_state[key]
    valid = list(options)
    if isinstance(value, list):
        kept = [v for v in value if v in valid]
        if kept != value:
            st.session_state[key] = kept
    elif value not in valid:
        del st.session_state[key]


def track_active_tab(fallback: str) -> None:
    """
    Copia a tab de topo ativa para uma chave que sobreviva ao próximo rerun.
    Chamar imediatamente depois de criar as tabs (ver ``ACTIVE_TAB_KEY``).
    """
    st.session_state[ACTIVE_TAB_KEY] = st.session_state.get(TAB_WIDGET_KEY) or fallback


def from_snapshot(key: str) -> Optional[str]:
    """
    Instante do snapshot, se ``key`` foi reposta do disco e ainda não foi
    regenerada nesta sessão; ``None`` caso contrário.

    Serve para a UI distinguir um resultado acabado de correr de um resultado
    gravado há dias — sem isto, um cenário reposto do disco apareceria como se
    tivesse acabado de ser executado.
    """
    return (st.session_state.get(_FROM_DISK) or {}).get(key)


def mark_fresh(key: str) -> None:
    """Marca ``key`` como gerada nesta sessão (chamar ao guardar um resultado novo)."""
    from_disk = st.session_state.get(_FROM_DISK)
    if from_disk:
        from_disk.pop(key, None)


def saved_at(username: str) -> Optional[str]:
    """Instante do snapshot em disco, sem o repor."""
    if _SAVED_AT in st.session_state:
        return st.session_state[_SAVED_AT]
    try:
        with open(path_for(username), encoding="utf-8") as fh:
            return json.load(fh).get("saved_at")
    except (OSError, ValueError):
        return None


def clear(username: str) -> bool:
    """Apaga o snapshot gravado. Devolve True se havia ficheiro para apagar."""
    try:
        os.remove(path_for(username))
    except FileNotFoundError:
        return False
    st.session_state.pop(_SAVED_AT, None)
    st.session_state[_FROM_DISK] = {}
    st.session_state[_CAME_FROM_DISK] = False
    return True


def request_shutdown(delay: float = 2.0) -> None:
    """
    Encerra o processo do servidor Streamlit ``delay`` segundos depois.

    O atraso existe para o browser ainda receber a página com a confirmação: o
    Streamlit só envia o que foi desenhado quando o script termina, pelo que
    sair de imediato deixaria o utilizador num ecrã em branco, sem saber se o
    estado ficou gravado. O snapshot já está em disco quando isto é chamado.
    """
    threading.Timer(delay, lambda: os._exit(0)).start()
