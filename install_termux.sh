#!/data/data/com.termux/files/usr/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  Probe2 — Auto Installer for Android Termux (clean install)
#  Запуск: curl -sL <raw-url> | bash   ИЛИ   bash install_termux.sh
# ═══════════════════════════════════════════════════════════════════════

set -e

C_RST="\033[0m"
C_B="\033[1m"
C_G="\033[92m"
C_R="\033[91m"
C_Y="\033[93m"
C_CY="\033[96m"

ok()   { echo -e "  ${C_G}✓${C_RST} $1"; }
fail() { echo -e "  ${C_R}✗${C_RST} $1"; exit 1; }
info() { echo -e "  ${C_CY}•${C_RST} $1"; }
warn() { echo -e "  ${C_Y}!${C_RST} $1"; }

REPO_URL="https://github.com/HighRareCoder/probe_bot.git"
WORK_DIR="$HOME/probe2"

echo -e "
  ${C_CY}${C_B}╔════════════════════════════════════════════════════════╗
  ║       P R O B E 2  —  Termux Installer              ║
  ╚════════════════════════════════════════════════════════╝${C_RST}
"

# ── 0. Проверка: мы в Termux? ──────────────────────────────────────
if [[ -z "$PREFIX" ]] || [[ "$PREFIX" != *"com.termux"* ]]; then
    warn "Не обнаружена среда Termux (PREFIX=$PREFIX)"
    echo -ne "  ${C_Y}Продолжить всё равно? (y/N):${C_RST} "
    read -r ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || fail "Отмена."
fi

# ── 1. Обновление пакетов ──────────────────────────────────────────
info "Обновление репозиториев Termux..."
pkg update -y 2>/dev/null && pkg upgrade -y 2>/dev/null
ok "Пакеты обновлены"

# ── 2. Системные зависимости ───────────────────────────────────────
info "Установка python, git, openssl..."
pkg install -y python git openssl-tool 2>/dev/null
ok "python, git, openssl установлены"

# ── 3. Хранилище (доступ к /sdcard) ───────────────────────────────
if ! ls /sdcard/ >/dev/null 2>&1; then
    info "Запрос доступа к хранилищу..."
    termux-setup-storage 2>/dev/null || true
    warn "Если появился диалог — разрешите доступ и перезапустите скрипт"
fi

# ── 4. Клонируем / обновляем репозиторий ───────────────────────────
if [ -d "$WORK_DIR/.git" ]; then
    info "Каталог $WORK_DIR уже существует — обновляю (git pull)..."
    cd "$WORK_DIR"
    git fetch --all 2>/dev/null
    git reset --hard origin/main 2>/dev/null || git reset --hard origin/master 2>/dev/null
    ok "Репозиторий обновлён"
else
    if [ -d "$WORK_DIR" ]; then
        warn "Каталог $WORK_DIR существует, но не git-репо — удаляю..."
        rm -rf "$WORK_DIR"
    fi
    info "Клонирую ${C_B}$REPO_URL${C_RST} ..."
    git clone "$REPO_URL" "$WORK_DIR"
    ok "Репозиторий склонирован в $WORK_DIR"
fi

cd "$WORK_DIR"

# ── 5. Python venv ─────────────────────────────────────────────────
VENV_DIR="$WORK_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
    info "Создаю виртуальное окружение (.venv)..."
    python -m venv "$VENV_DIR"
    ok "venv создан: $VENV_DIR"
else
    info "venv уже существует, пропускаю создание"
fi

# Активируем venv для текущей сессии
source "$VENV_DIR/bin/activate"
ok "venv активирован"

# ── 6. Python-зависимости ──────────────────────────────────────────
info "Обновляю pip..."
pip install --upgrade pip 2>/dev/null || true

if [ -f "$WORK_DIR/requirements.txt" ]; then
    info "Установка зависимостей из requirements.txt..."
    pip install -r "$WORK_DIR/requirements.txt" 2>/dev/null
else
    info "requirements.txt не найден — ставлю базовые пакеты..."
    pip install requests pyyaml 2>/dev/null
fi
ok "pip-пакеты установлены"

# ── 7. sing-box (автоскачивание) ───────────────────────────────────
info "Проверка sing-box..."

SINGBOX_BIN=""
if command -v sing-box >/dev/null 2>&1; then
    SINGBOX_BIN="$(command -v sing-box)"
    ok "sing-box найден в PATH: $SINGBOX_BIN"
elif [ -f "$WORK_DIR/bin/sing-box" ]; then
    SINGBOX_BIN="$WORK_DIR/bin/sing-box"
    ok "sing-box найден: $SINGBOX_BIN"
fi

if [ -z "$SINGBOX_BIN" ]; then
    if [ -f "$WORK_DIR/singbox_download.py" ]; then
        info "sing-box не найден — запускаю автозагрузку..."
        python "$WORK_DIR/singbox_download.py" 2>/dev/null && ok "sing-box скачан" || {
            warn "Автозагрузка не удалась, пробую через pkg..."
            pkg install -y sing-box 2>/dev/null || warn "sing-box не установлен — установите вручную"
        }
    else
        info "singbox_download.py не найден, пробую pkg install..."
        pkg install -y sing-box 2>/dev/null || warn "sing-box не установлен — установите вручную"
    fi
fi

[ -f "$WORK_DIR/bin/sing-box" ] && chmod +x "$WORK_DIR/bin/sing-box"

# ── 8. Финальная проверка ──────────────────────────────────────────
echo ""
info "Финальная проверка..."

PYTHON_OK=false; REQUESTS_OK=false; YAML_OK=false; SINGBOX_OK=false

python --version >/dev/null 2>&1 && PYTHON_OK=true
python -c "import requests" 2>/dev/null && REQUESTS_OK=true
python -c "import yaml" 2>/dev/null && YAML_OK=true
{ command -v sing-box >/dev/null 2>&1 || [ -f "$WORK_DIR/bin/sing-box" ]; } && SINGBOX_OK=true

echo ""
echo -e "  ${C_CY}${C_B}Статус компонентов:${C_RST}"
echo -e "  ──────────────────────────────────────"
$PYTHON_OK   && ok "Python 3            $(python --version 2>&1)" || warn "Python 3"
$REQUESTS_OK && ok "requests            $(python -c 'import requests; print(requests.__version__)' 2>/dev/null)" || warn "requests"
$YAML_OK     && ok "PyYAML              $(python -c 'import yaml; print(yaml.__version__)' 2>/dev/null)" || warn "PyYAML"
$SINGBOX_OK  && ok "sing-box" || warn "sing-box (не критично — скачается при первом запуске)"
echo -e "  ──────────────────────────────────────"

if ! $PYTHON_OK || ! $REQUESTS_OK; then
    fail "Критические компоненты не установлены — см. ошибки выше"
fi

# ── 9. Создаём launcher-скрипт ─────────────────────────────────────
LAUNCHER="$HOME/probe2_run.sh"
cat > "$LAUNCHER" << 'LAUNCHER_EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$HOME/probe2" && source .venv/bin/activate && python probe2.py "$@"
LAUNCHER_EOF
chmod +x "$LAUNCHER"
ok "Быстрый запуск: ${C_B}~/probe2_run.sh${C_RST}"

# ── 10. Termux:Boot автозапуск (опционально) ───────────────────────
echo ""
echo -ne "  ${C_Y}Настроить автозапуск при загрузке? (требуется Termux:Boot) (y/N):${C_RST} "
read -r autostart

if [[ "$autostart" == "y" || "$autostart" == "Y" ]]; then
    BOOT_DIR="$HOME/.termux/boot"
    mkdir -p "$BOOT_DIR"
    cat > "$BOOT_DIR/probe2-autostart.sh" << 'BOOT_EOF'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
cd "$HOME/probe2" && source .venv/bin/activate && python probe2.py >> "$HOME/probe2/probe2.log" 2>&1 &
BOOT_EOF
    chmod +x "$BOOT_DIR/probe2-autostart.sh"
    ok "Автозапуск настроен: $BOOT_DIR/probe2-autostart.sh"
    warn "Установите Termux:Boot из F-Droid и откройте его один раз"
else
    info "Автозапуск пропущен"
fi

# ── 11. Запуск бота ────────────────────────────────────────────────
echo ""
echo -e "  ${C_G}${C_B}Установка завершена!${C_RST}"
echo ""
echo -e "  ${C_CY}Справка по запуску:${C_RST}"
echo -e "    ${C_B}~/probe2_run.sh${C_RST}                   — быстрый запуск"
echo -e "    ${C_B}~/probe2_run.sh 'vless://...'${C_RST}     — проверка одного конфига"
echo ""
echo -e "  ${C_CY}Через tmux (рекомендуется):${C_RST}"
echo -e "    ${C_B}pkg install tmux${C_RST}"
echo -e "    ${C_B}tmux new -s probe${C_RST}"
echo -e "    ${C_B}~/probe2_run.sh${C_RST}"
echo -e "    ${C_Y}(Ctrl+B, D — отсоединиться; tmux attach -t probe — вернуться)${C_RST}"
echo ""

echo -ne "  ${C_CY}Запустить бота сейчас? (Y/n):${C_RST} "
read -r run_now

if [[ "$run_now" != "n" && "$run_now" != "N" ]]; then
    echo ""
    ok "Запускаю probe2..."
    echo -e "  ──────────────────────────────────────"
    echo ""
    exec python "$WORK_DIR/probe2.py" "$@"
else
    echo ""
    echo -e "  ${C_G}${C_B}Готово! Запуск:  ~/probe2_run.sh${C_RST}"
    echo ""
fi
