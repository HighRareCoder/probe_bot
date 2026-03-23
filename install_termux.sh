#!/data/data/com.termux/files/usr/bin/bash
# ═══════════════════════════════════════════════════════════════════════
#  Probe2 — Auto Installer for Android Termux
#  Запуск: bash install_termux.sh
# ═══════════════════════════════════════════════════════════════════════

set -e

C_RST="\033[0m"
C_B="\033[1m"
C_G="\033[92m"
C_R="\033[91m"
C_Y="\033[93m"
C_CY="\033[96m"

ok()   { echo -e "  ${C_G}✓${C_RST} $1"; }
fail() { echo -e "  ${C_R}✗${C_RST} $1"; }
info() { echo -e "  ${C_CY}•${C_RST} $1"; }
warn() { echo -e "  ${C_Y}!${C_RST} $1"; }

echo -e "
  ${C_CY}${C_B}╔════════════════════════════════════════════════════════╗
  ║       P R O B E 2  —  Termux Installer              ║
  ╚════════════════════════════════════════════════════════╝${C_RST}
"

# ── Проверка: мы в Termux? ───────────────────────────────────────────
if [[ -z "$PREFIX" ]] || [[ "$PREFIX" != *"com.termux"* ]]; then
    warn "Не обнаружена среда Termux (PREFIX=$PREFIX)"
    warn "Скрипт рассчитан на Termux. Продолжить? (y/N)"
    read -r ans
    if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
        fail "Отмена."
        exit 1
    fi
fi

# ── 1. Обновление пакетов ────────────────────────────────────────────
info "Обновление репозиториев Termux..."
pkg update -y 2>/dev/null && pkg upgrade -y 2>/dev/null
ok "Пакеты обновлены"

# ── 2. Установка системных зависимостей ──────────────────────────────
info "Установка python, git, openssl..."
pkg install -y python git openssl-tool 2>/dev/null
ok "python, git, openssl установлены"

# ── 3. Хранилище (для доступа к /sdcard, если нужно) ─────────────────
if ! ls /sdcard/ >/dev/null 2>&1; then
    info "Запрос доступа к хранилищу..."
    termux-setup-storage 2>/dev/null || true
    warn "Если появился диалог — разрешите доступ и перезапустите скрипт"
fi

# ── 4. Определяем рабочую директорию ─────────────────────────────────
WORK_DIR="$HOME/probe2"
info "Рабочая директория: ${C_B}$WORK_DIR${C_RST}"

if [ -d "$WORK_DIR" ]; then
    warn "Каталог $WORK_DIR уже существует"
    warn "Перезаписать? (y/N)"
    read -r ans
    if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
        info "Пропуск загрузки файлов, обновляю зависимости..."
    else
        rm -rf "$WORK_DIR"
    fi
fi

# ── 5. Получение файлов проекта ──────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$WORK_DIR" ]; then
    mkdir -p "$WORK_DIR"

    # Если скрипт лежит рядом с probe2.py — копируем локально
    if [ -f "$SCRIPT_DIR/probe2.py" ]; then
        info "Копирование файлов из $SCRIPT_DIR ..."
        for f in probe2.py singbox_download.py config.yaml requirements.txt; do
            if [ -f "$SCRIPT_DIR/$f" ]; then
                cp "$SCRIPT_DIR/$f" "$WORK_DIR/$f"
                ok "  $f"
            fi
        done
    else
        fail "probe2.py не найден рядом с установщиком"
        fail "Поместите install_termux.sh в папку с probe2.py и перезапустите"
        exit 1
    fi
fi

cd "$WORK_DIR"

# ── 6. Python-зависимости ────────────────────────────────────────────
info "Установка pip-пакетов (requests, pyyaml)..."
pip install --upgrade pip 2>/dev/null || true
pip install requests pyyaml 2>/dev/null
ok "pip-пакеты установлены"

# ── 7. sing-box (автоскачивание) ─────────────────────────────────────
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
    info "sing-box не найден — запускаю автозагрузку через Python..."
    python -c "
import sys, os
sys.path.insert(0, '$WORK_DIR')
import singbox_download
result = singbox_download.ensure_singbox('$WORK_DIR', quiet=False)
if result:
    print(f'  OK: {result}')
else:
    print('  FAIL: не удалось скачать sing-box')
    sys.exit(1)
"
    if [ $? -eq 0 ]; then
        ok "sing-box скачан"
    else
        fail "Не удалось скачать sing-box автоматически"
        warn "Попробуйте установить вручную: pkg install sing-box"
        pkg install -y sing-box 2>/dev/null || true
    fi
fi

# Проставляем chmod на всякий случай
if [ -f "$WORK_DIR/bin/sing-box" ]; then
    chmod +x "$WORK_DIR/bin/sing-box"
fi

# ── 8. Проверка что всё работает ─────────────────────────────────────
echo ""
info "Финальная проверка..."

PYTHON_OK=false
REQUESTS_OK=false
YAML_OK=false
SINGBOX_OK=false

python --version >/dev/null 2>&1 && PYTHON_OK=true
python -c "import requests" 2>/dev/null && REQUESTS_OK=true
python -c "import yaml" 2>/dev/null && YAML_OK=true

if command -v sing-box >/dev/null 2>&1 || [ -f "$WORK_DIR/bin/sing-box" ]; then
    SINGBOX_OK=true
fi

echo ""
echo -e "  ${C_CY}${C_B}Статус компонентов:${C_RST}"
echo -e "  ──────────────────────────────────────"
$PYTHON_OK   && ok "Python 3            $(python --version 2>&1)" || fail "Python 3"
$REQUESTS_OK && ok "requests            $(python -c 'import requests; print(requests.__version__)' 2>/dev/null)" || fail "requests"
$YAML_OK     && ok "PyYAML              $(python -c 'import yaml; print(yaml.__version__)' 2>/dev/null)" || fail "PyYAML"
$SINGBOX_OK  && ok "sing-box" || fail "sing-box"
echo -e "  ──────────────────────────────────────"

if $PYTHON_OK && $REQUESTS_OK && $SINGBOX_OK; then
    echo ""
    ok "${C_G}${C_B}Установка завершена!${C_RST}"
    echo ""
    echo -e "  ${C_CY}Запуск:${C_RST}"
    echo -e "    ${C_B}cd ~/probe2${C_RST}"
    echo -e "    ${C_B}python probe2.py${C_RST}"
    echo ""
    echo -e "  ${C_CY}Или однократная проверка одного конфига:${C_RST}"
    echo -e "    ${C_B}python probe2.py 'vless://...'${C_RST}"
    echo ""
    echo -e "  ${C_CY}Запуск в фоне (не умрёт при сворачивании Termux):${C_RST}"
    echo -e "    ${C_B}nohup python probe2.py > probe2.log 2>&1 &${C_RST}"
    echo ""
    echo -e "  ${C_CY}Или через tmux (рекомендуется):${C_RST}"
    echo -e "    ${C_B}pkg install tmux${C_RST}"
    echo -e "    ${C_B}tmux new -s probe${C_RST}"
    echo -e "    ${C_B}python probe2.py${C_RST}"
    echo -e "    ${C_Y}(Ctrl+B, затем D — отсоединиться; tmux attach -t probe — вернуться)${C_RST}"
    echo ""
else
    echo ""
    fail "Некоторые компоненты не установлены — см. ошибки выше"
    exit 1
fi

# ── 9. Создаём быстрый launcher ──────────────────────────────────────
LAUNCHER="$HOME/probe2_run.sh"
cat > "$LAUNCHER" << 'LAUNCHER_EOF'
#!/data/data/com.termux/files/usr/bin/bash
cd "$HOME/probe2" && python probe2.py "$@"
LAUNCHER_EOF
chmod +x "$LAUNCHER"
ok "Быстрый запуск: ${C_B}~/probe2_run.sh${C_RST}"

# ── 10. Termux:Boot автозапуск (опционально) ─────────────────────────
echo ""
echo -e "  ${C_Y}Настроить автозапуск при загрузке устройства?${C_RST}"
echo -e "  ${C_Y}(требуется приложение Termux:Boot из F-Droid)${C_RST}"
echo -e "  ${C_Y}(y/N):${C_RST} \c"
read -r autostart

if [[ "$autostart" == "y" || "$autostart" == "Y" ]]; then
    BOOT_DIR="$HOME/.termux/boot"
    mkdir -p "$BOOT_DIR"
    cat > "$BOOT_DIR/probe2-autostart.sh" << 'BOOT_EOF'
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
cd "$HOME/probe2" && python probe2.py >> "$HOME/probe2/probe2.log" 2>&1 &
BOOT_EOF
    chmod +x "$BOOT_DIR/probe2-autostart.sh"
    ok "Автозапуск настроен: $BOOT_DIR/probe2-autostart.sh"
    warn "Установите Termux:Boot из F-Droid и откройте его один раз"
else
    info "Автозапуск пропущен"
fi

echo ""
echo -e "  ${C_G}${C_B}Готово! 🎉${C_RST}"
echo ""
