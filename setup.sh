#!/usr/bin/env bash
# VPN Server Setup Script
# Installs: UFW, fail2ban, ICMP blocking, 3x-ui (VLESS+Reality), telemt (MTProto)
set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL VARIABLES
# ─────────────────────────────────────────────────────────────────────────────
LANG_CODE="en"
INSTALL_MODE="quick"
SSH_PORT=22
TELEMT_PORT=8443
SERVER_IP=""
PANEL_USER=""
PANEL_PASS=""
VLESS_UUID=""
VLESS_PUBLIC_KEY=""
VLESS_PRIVATE_KEY=""
VLESS_SHORT_ID=""
VLESS_SNI="www.microsoft.com"
VLESS_LINK=""
TELEMT_SECRET=""
TELEMT_LINK=""
PANEL_PROTO="http"
SSL_CERT_ISSUED=false
LOG_FILE="/var/log/server-setup.log"
CREDS_FILE="/root/server-credentials.txt"

# ─────────────────────────────────────────────────────────────────────────────
# i18n STRINGS
# ─────────────────────────────────────────────────────────────────────────────
declare -A MSG_EN MSG_RU

# Step 0
MSG_EN[LANG_SELECT]="Select language / Выберите язык:\n  [1] English\n  [2] Русский\nYour choice: "
MSG_RU[LANG_SELECT]="${MSG_EN[LANG_SELECT]}"
MSG_EN[MODE_SELECT]="Select install mode:\n  [1] Quick install (all defaults)\n  [2] Step-by-step (confirm each step)\nYour choice: "
MSG_RU[MODE_SELECT]="Выберите режим установки:\n  [1] Быстрая установка (все по умолчанию)\n  [2] Пошаговая установка (подтверждение каждого шага)\nВаш выбор: "
MSG_EN[MODE_QUICK]="Quick install mode selected."
MSG_RU[MODE_QUICK]="Выбран режим быстрой установки."
MSG_EN[MODE_STEP]="Step-by-step install mode selected."
MSG_RU[MODE_STEP]="Выбран пошаговый режим установки."

# Step 1
MSG_EN[STEP1_START]="[Step 1] Updating system packages..."
MSG_RU[STEP1_START]="[Шаг 1] Обновление системных пакетов..."
MSG_EN[STEP1_OK]="System update complete."
MSG_RU[STEP1_OK]="Обновление системы завершено."

# Step 2
MSG_EN[STEP2_START]="[Step 2] SSH port configuration"
MSG_RU[STEP2_START]="[Шаг 2] Настройка SSH-порта"
MSG_EN[SSH_PORT_PROMPT]="Enter new SSH port [Enter to keep %s]: "
MSG_RU[SSH_PORT_PROMPT]="Введите новый SSH-порт [Enter — оставить %s]: "
MSG_EN[SSH_PORT_INVALID]="Invalid port value, keeping port %s."
MSG_RU[SSH_PORT_INVALID]="Некорректный номер порта, оставляем %s."
MSG_EN[SSH_PORT_UNCHANGED]="SSH port unchanged (%s)."
MSG_RU[SSH_PORT_UNCHANGED]="SSH-порт не изменён (%s)."
MSG_EN[SSH_WARN_SESSION]="WARNING: Do not close the current session until you have verified the new SSH port!"
MSG_RU[SSH_WARN_SESSION]="ВНИМАНИЕ: Не закрывайте текущую сессию до проверки нового SSH-порта!"
MSG_EN[SSH_PORT_CHANGED]="SSH port changed to %s."
MSG_RU[SSH_PORT_CHANGED]="SSH-порт изменён на %s."
MSG_EN[SSH_PORT_REVERT]="Failed to restart sshd, reverting SSH port to %s."
MSG_RU[SSH_PORT_REVERT]="Не удалось перезапустить sshd, откат SSH-порта на %s."

# Step 3
MSG_EN[STEP3_START]="[Step 3] Root password configuration"
MSG_RU[STEP3_START]="[Шаг 3] Настройка пароля root"
MSG_EN[ROOT_PASS_CHANGE]="Change root password? [y/N]: "
MSG_RU[ROOT_PASS_CHANGE]="Сменить пароль root? [y/N]: "
MSG_EN[ROOT_PASS_HOW]="  [1] Generate secure password\n  [2] Enter manually\nYour choice: "
MSG_RU[ROOT_PASS_HOW]="  [1] Сгенерировать надёжный пароль\n  [2] Ввести вручную\nВаш выбор: "
MSG_EN[ROOT_PASS_MANUAL]="Enter new root password: "
MSG_RU[ROOT_PASS_MANUAL]="Введите новый пароль root: "
MSG_EN[ROOT_PASS_GENERATED]="Generated password (save it now, not stored in logs):"
MSG_RU[ROOT_PASS_GENERATED]="Сгенерированный пароль (сохраните сейчас, в лог не пишется):"
MSG_EN[ROOT_PASS_PRESS_ENTER]="Press Enter after saving the password..."
MSG_RU[ROOT_PASS_PRESS_ENTER]="Нажмите Enter после сохранения пароля..."
MSG_EN[ROOT_PASS_OK]="Root password updated."
MSG_RU[ROOT_PASS_OK]="Пароль root обновлён."
MSG_EN[ROOT_PASS_SKIPPED]="Root password not changed."
MSG_RU[ROOT_PASS_SKIPPED]="Пароль root не изменён."

# Step 4
MSG_EN[STEP4_START]="[Step 4] Configuring UFW firewall..."
MSG_RU[STEP4_START]="[Шаг 4] Настройка файрвола UFW..."
MSG_EN[STEP4_OK]="UFW configured and enabled."
MSG_RU[STEP4_OK]="UFW настроен и включён."

# Step 5
MSG_EN[STEP5_START]="[Step 5] Installing fail2ban..."
MSG_RU[STEP5_START]="[Шаг 5] Установка fail2ban..."
MSG_EN[STEP5_OK]="fail2ban installed and configured."
MSG_RU[STEP5_OK]="fail2ban установлен и настроен."
MSG_EN[STEP5_FAIL]="fail2ban installation failed, continuing."
MSG_RU[STEP5_FAIL]="Не удалось установить fail2ban, продолжаем."

# Step 6
MSG_EN[STEP6_START]="[Step 6] Blocking ICMP (ping)..."
MSG_RU[STEP6_START]="[Шаг 6] Блокировка ICMP (ping)..."
MSG_EN[STEP6_OK]="ICMP blocked."
MSG_RU[STEP6_OK]="ICMP заблокирован."
MSG_EN[STEP6_FAIL]="ICMP blocking failed, continuing."
MSG_RU[STEP6_FAIL]="Не удалось заблокировать ICMP, продолжаем."

# Step 7
MSG_EN[STEP7_START]="[Step 7] Installing 3x-ui + VLESS+Reality..."
MSG_RU[STEP7_START]="[Шаг 7] Установка 3x-ui + VLESS+Reality..."
MSG_EN[SSL_START]="  [7.1] Issuing SSL certificate for IP %s..."
MSG_RU[SSL_START]="  [7.1] Выпуск SSL-сертификата для IP %s..."
MSG_EN[SSL_OK]="  SSL certificate issued. Port 80 closed."
MSG_RU[SSL_OK]="  SSL-сертификат выпущен. Порт 80 закрыт."
MSG_EN[SSL_FAIL]="  SSL certificate failed, panel will use HTTP."
MSG_RU[SSL_FAIL]="  Не удалось выпустить SSL-сертификат, панель будет работать по HTTP."
MSG_EN[XUID_START]="  [7.2] Installing 3x-ui panel..."
MSG_RU[XUID_START]="  [7.2] Установка панели 3x-ui..."
MSG_EN[XUID_OK]="  3x-ui installed."
MSG_RU[XUID_OK]="  3x-ui установлен."
MSG_EN[XUID_FAIL]="  3x-ui installation failed, skipping VLESS setup."
MSG_RU[XUID_FAIL]="  Не удалось установить 3x-ui, пропускаем настройку VLESS."
MSG_EN[SNI_START]="  [7.3] Scanning for SNI..."
MSG_RU[SNI_START]="  [7.3] Сканирование SNI..."
MSG_EN[SNI_FOUND]="  SNI found: %s"
MSG_RU[SNI_FOUND]="  Найден SNI: %s"
MSG_EN[SNI_PROMPT]="  Press Enter to use '%s' or enter a different SNI: "
MSG_RU[SNI_PROMPT]="  Нажмите Enter для использования '%s' или введите свой SNI: "
MSG_EN[SNI_FALLBACK]="  No SNI found, using fallback: %s"
MSG_RU[SNI_FALLBACK]="  SNI не найден, используем запасной: %s"
MSG_EN[INBOUND_START]="  [7.4] Creating VLESS+Reality inbound..."
MSG_RU[INBOUND_START]="  [7.4] Создание VLESS+Reality inbound..."
MSG_EN[INBOUND_OK]="  VLESS+Reality inbound created."
MSG_RU[INBOUND_OK]="  VLESS+Reality inbound создан."
MSG_EN[INBOUND_FAIL]="  Failed to create VLESS inbound via API."
MSG_RU[INBOUND_FAIL]="  Не удалось создать VLESS inbound через API."

# Step 8
MSG_EN[STEP8_START]="[Step 8] Installing telemt (MTProto for Telegram)..."
MSG_RU[STEP8_START]="[Шаг 8] Установка telemt (MTProto для Telegram)..."
MSG_EN[TELEMT_PORT_PROMPT]="Enter telemt port [Enter to use %s]: "
MSG_RU[TELEMT_PORT_PROMPT]="Введите порт telemt [Enter — использовать %s]: "
MSG_EN[STEP8_OK]="telemt installed."
MSG_RU[STEP8_OK]="telemt установлен."
MSG_EN[STEP8_FAIL]="telemt installation failed."
MSG_RU[STEP8_FAIL]="Не удалось установить telemt."
MSG_EN[ALREADY_INSTALLED]="%s already installed, skipping reinstall."
MSG_RU[ALREADY_INSTALLED]="%s уже установлен, переустановка не требуется."
MSG_EN[UNREACHABLE_SKIP]="%s is unreachable, skipping."
MSG_RU[UNREACHABLE_SKIP]="%s недоступен, пропускаем."
MSG_EN[UNSUPPORTED_SKIP]="%s does not support required flags, skipping."
MSG_RU[UNSUPPORTED_SKIP]="%s не поддерживает нужные флаги, пропускаем."

# Summary
MSG_EN[SUMMARY_TITLE]="INSTALLATION COMPLETE"
MSG_RU[SUMMARY_TITLE]="УСТАНОВКА ЗАВЕРШЕНА"
MSG_EN[SUMMARY_SSH]="SSH port"
MSG_RU[SUMMARY_SSH]="SSH порт"
MSG_EN[SUMMARY_PANEL_TITLE]="3X-UI PANEL"
MSG_RU[SUMMARY_PANEL_TITLE]="3X-UI ПАНЕЛЬ"
MSG_EN[SUMMARY_PANEL_URL]="URL"
MSG_RU[SUMMARY_PANEL_URL]="Адрес"
MSG_EN[SUMMARY_PANEL_USER]="Login"
MSG_RU[SUMMARY_PANEL_USER]="Логин"
MSG_EN[SUMMARY_PANEL_PASS]="Password"
MSG_RU[SUMMARY_PANEL_PASS]="Пароль"
MSG_EN[SUMMARY_VLESS_TITLE]="VLESS+REALITY (import into client)"
MSG_RU[SUMMARY_VLESS_TITLE]="VLESS+REALITY (скопируйте в клиент)"
MSG_EN[SUMMARY_TG_TITLE]="TELEGRAM PROXY"
MSG_RU[SUMMARY_TG_TITLE]="TELEGRAM ПРОКСИ"
MSG_EN[SUMMARY_SSL_INFO]="SSL certificate expires in ~6 days. Auto-renewal via cron is configured."
MSG_RU[SUMMARY_SSL_INFO]="SSL-сертификат истекает через ~6 дней. Авторенью настроено через cron."
MSG_EN[SUMMARY_NO_SSL]="Panel running over HTTP (no SSL certificate)."
MSG_RU[SUMMARY_NO_SSL]="Панель работает по HTTP (SSL-сертификат не выпущен)."
MSG_EN[SUMMARY_NO_VLESS]="VLESS+Reality not configured (3x-ui installation failed)."
MSG_RU[SUMMARY_NO_VLESS]="VLESS+Reality не настроен (ошибка установки 3x-ui)."
MSG_EN[SUMMARY_NO_TG]="Telegram proxy not configured (telemt installation failed)."
MSG_RU[SUMMARY_NO_TG]="Telegram-прокси не настроен (ошибка установки telemt)."
MSG_EN[SUMMARY_SAVED]="Credentials also saved to %s"
MSG_RU[SUMMARY_SAVED]="Данные также сохранены в %s"
MSG_EN[SUMMARY_SECURITY_TITLE]="SECURITY RECOMMENDATION"
MSG_RU[SUMMARY_SECURITY_TITLE]="РЕКОМЕНДАЦИЯ ПО БЕЗОПАСНОСТИ"
MSG_EN[SUMMARY_SECURITY_TEXT1]="Password login is still enabled on SSH."
MSG_RU[SUMMARY_SECURITY_TEXT1]="Вход по паролю через SSH всё ещё включён."
MSG_EN[SUMMARY_SECURITY_TEXT2]="Set up SSH key auth, then set 'PasswordAuthentication no'."
MSG_RU[SUMMARY_SECURITY_TEXT2]="Настройте вход по SSH-ключу, затем установите 'PasswordAuthentication no'."

# Generic
MSG_EN[ERR_NOT_ROOT]="Error: this script must be run as root."
MSG_RU[ERR_NOT_ROOT]="Ошибка: скрипт должен быть запущен от root."
MSG_EN[ERR_CRITICAL]="Critical error: %s. Aborting."
MSG_RU[ERR_CRITICAL]="Критическая ошибка: %s. Прерывание."
MSG_EN[WARN_SKIP]="Warning: %s failed, continuing."
MSG_RU[WARN_SKIP]="Предупреждение: %s не выполнен, продолжаем."
MSG_EN[DEPS_START]="Checking and installing dependencies..."
MSG_RU[DEPS_START]="Проверка и установка зависимостей..."

# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

t() {
    local key="$1"
    local template=""
    if [[ "$LANG_CODE" == "ru" ]]; then
        template="${MSG_RU[$key]:-${MSG_EN[$key]:-$key}}"
    else
        template="${MSG_EN[$key]:-$key}"
    fi
    if [[ $# -gt 1 ]]; then
        # shellcheck disable=SC2059
        printf "$template" "${@:2}"
    else
        printf "%s" "$template"
    fi
}

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    printf '[%s] [%s] %s\n' "$timestamp" "$level" "$message" >> "$LOG_FILE"
}

msg() {
    printf '%s\n' "$*"
    log "INFO" "$*"
}

warn() {
    printf '\033[33m%s\033[0m\n' "$*"
    log "WARN" "$*"
}

run_critical() {
    local desc="$1"; shift
    log "INFO" "Running (critical): $desc"
    if ! "$@"; then
        local err_msg
        err_msg=$(t ERR_CRITICAL "$desc")
        printf '\033[31m%s\033[0m\n' "$err_msg" >&2
        log "ERROR" "CRITICAL FAILURE: $desc"
        exit 1
    fi
}

run_safe() {
    local desc="$1"; shift
    log "INFO" "Running: $desc"
    if ! "$@"; then
        warn "$(t WARN_SKIP "$desc")"
        return 1
    fi
    return 0
}

prompt_user() {
    local varname="$1"
    local prompt_text="$2"
    local default="$3"

    if [[ "$INSTALL_MODE" == "quick" ]]; then
        printf -v "$varname" '%s' "$default"
        log "INFO" "Quick mode: $varname set to default"
        return
    fi

    printf '%s' "$prompt_text"
    local input
    read -r input
    if [[ -z "$input" ]]; then
        printf -v "$varname" '%s' "$default"
    else
        printf -v "$varname" '%s' "$input"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP (EXIT TRAP)
# ─────────────────────────────────────────────────────────────────────────────

cleanup_on_exit() {
    rm -f /tmp/RealiTLScanner /tmp/reality_scan.csv \
          /tmp/3xui_session.txt /tmp/3xui_install.sh 2>/dev/null || true
}
trap cleanup_on_exit EXIT

# ─────────────────────────────────────────────────────────────────────────────
# DEPENDENCIES
# ─────────────────────────────────────────────────────────────────────────────

install_dependencies() {
    msg "$(t DEPS_START)"
    local deps=(curl wget ufw fail2ban openssl expect jq uuid-runtime)
    apt-get update -qq >> "$LOG_FILE" 2>&1 || true
    for dep in "${deps[@]}"; do
        if ! dpkg -l "$dep" > /dev/null 2>&1; then
            apt-get install -y "$dep" >> "$LOG_FILE" 2>&1 \
                && log "INFO" "Installed: $dep" \
                || log "WARN" "Failed to install: $dep"
        fi
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0: LANGUAGE & MODE SELECTION
# ─────────────────────────────────────────────────────────────────────────────

step_0_language() {
    printf '%b' "$(t LANG_SELECT)"
    local lang_choice
    read -r lang_choice
    case "$lang_choice" in
        2) LANG_CODE="ru" ;;
        *) LANG_CODE="en" ;;
    esac
    log "INFO" "Language selected: $LANG_CODE"

    printf '\n%b' "$(t MODE_SELECT)"
    local mode_choice
    read -r mode_choice
    case "$mode_choice" in
        2) INSTALL_MODE="step"; msg "$(t MODE_STEP)" ;;
        *) INSTALL_MODE="quick"; msg "$(t MODE_QUICK)" ;;
    esac
    log "INFO" "Install mode: $INSTALL_MODE"

    # Collect ports upfront so UFW (step 4) knows them before we run
    if [[ "$INSTALL_MODE" == "step" ]]; then
        local ssh_input
        printf '%b' "$(t SSH_PORT_PROMPT "$SSH_PORT")"
        read -r ssh_input
        if [[ -n "$ssh_input" ]]; then SSH_PORT="$ssh_input"; fi

        local telemt_input
        printf '%b' "$(t TELEMT_PORT_PROMPT "$TELEMT_PORT")"
        read -r telemt_input
        if [[ -n "$telemt_input" && "$telemt_input" =~ ^[0-9]+$ ]]; then
            TELEMT_PORT="$telemt_input"
        fi
    fi

    log "INFO" "SSH_PORT=$SSH_PORT, TELEMT_PORT=$TELEMT_PORT"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: SYSTEM UPDATE (CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_1_system_update() {
    msg "$(t STEP1_START)"
    DEBIAN_FRONTEND=noninteractive apt-get update >> "$LOG_FILE" 2>&1 \
        && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >> "$LOG_FILE" 2>&1
    msg "$(t STEP1_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: SSH PORT (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_2_ssh_port() {
    msg "$(t STEP2_START)"

    # SSH_PORT was already collected in step_0 for step mode.
    # In quick mode it stays at 22.

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
        warn "$(t SSH_PORT_INVALID "22")"
        SSH_PORT=22
        return
    fi

    if [[ "$SSH_PORT" == "22" ]]; then
        msg "$(t SSH_PORT_UNCHANGED "22")"
        return
    fi

    # Add UFW rule BEFORE touching sshd_config to avoid lockout
    ufw allow "${SSH_PORT}/tcp" >> "$LOG_FILE" 2>&1

    # Update sshd_config
    if grep -qE '^#?Port ' /etc/ssh/sshd_config; then
        sed -i "s|^#\?Port .*|Port ${SSH_PORT}|" /etc/ssh/sshd_config
    else
        echo "Port ${SSH_PORT}" >> /etc/ssh/sshd_config
    fi

    warn "$(t SSH_WARN_SESSION)"

    if ! systemctl restart sshd >> "$LOG_FILE" 2>&1; then
        warn "$(t SSH_PORT_REVERT "22")"
        sed -i "s|^Port ${SSH_PORT}|Port 22|" /etc/ssh/sshd_config
        ufw delete allow "${SSH_PORT}/tcp" >> "$LOG_FILE" 2>&1 || true
        SSH_PORT=22
    else
        msg "$(t SSH_PORT_CHANGED "$SSH_PORT")"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: ROOT PASSWORD (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_3_root_password() {
    msg "$(t STEP3_START)"

    if [[ "$INSTALL_MODE" != "step" ]]; then
        msg "$(t ROOT_PASS_SKIPPED)"
        return
    fi

    printf '%b' "$(t ROOT_PASS_CHANGE)"
    local yn
    read -r yn
    if [[ ! "$yn" =~ ^[yYдД]$ ]]; then
        msg "$(t ROOT_PASS_SKIPPED)"
        return
    fi

    printf '%b' "$(t ROOT_PASS_HOW)"
    local how
    read -r how

    local new_pass=""
    if [[ "$how" == "1" ]]; then
        new_pass=$(openssl rand -base64 16)
        printf '%s\n' "$(t ROOT_PASS_GENERATED)"
        printf '%s\n' "$new_pass"
        printf '%b' "$(t ROOT_PASS_PRESS_ENTER)"
        read -r _
    else
        printf '%b' "$(t ROOT_PASS_MANUAL)"
        read -rs new_pass
        printf '\n'
    fi

    if [[ -n "$new_pass" ]]; then
        printf '%s:%s\n' "root" "$new_pass" | chpasswd
        log "INFO" "Root password changed (value not logged)"
        msg "$(t ROOT_PASS_OK)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: UFW FIREWALL (CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_4_ufw() {
    msg "$(t STEP4_START)"
    ufw default deny incoming >> "$LOG_FILE" 2>&1
    ufw default allow outgoing >> "$LOG_FILE" 2>&1
    ufw allow "${SSH_PORT}/tcp" >> "$LOG_FILE" 2>&1
    ufw allow 80/tcp >> "$LOG_FILE" 2>&1
    ufw allow 2053/tcp >> "$LOG_FILE" 2>&1
    ufw allow 443/tcp >> "$LOG_FILE" 2>&1
    ufw allow "${TELEMT_PORT}/tcp" >> "$LOG_FILE" 2>&1
    ufw --force enable >> "$LOG_FILE" 2>&1
    msg "$(t STEP4_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: FAIL2BAN (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_5_fail2ban() {
    msg "$(t STEP5_START)"

    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >> "$LOG_FILE" 2>&1; then
        warn "$(t STEP5_FAIL)"
        return
    fi

    cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled  = true
port     = ${SSH_PORT}
maxretry = 5
bantime  = 3600
findtime = 600
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 604800
EOF

    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    msg "$(t STEP5_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: BLOCK ICMP (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

_block_icmp_in_file() {
    local file="$1"
    local is_ipv4="${2:-true}"

    if [[ ! -f "$file" ]]; then
        log "WARN" "File not found: $file"
        return 1
    fi

    cp -f "$file" "${file}.bak" 2>/dev/null || true

    # Replace ACCEPT → DROP for all icmp lines in INPUT and FORWARD chains
    if [[ "$is_ipv4" == "true" ]]; then
        sed -i '/ufw-before-input.*-p icmp/s/-j ACCEPT/-j DROP/g' "$file"
        sed -i '/ufw-before-forward.*-p icmp/s/-j ACCEPT/-j DROP/g' "$file"
        # Add source-quench DROP before echo-request line if not already present
        if ! grep -q 'source-quench' "$file"; then
            sed -i '/--icmp-type echo-request/i\-A ufw-before-input -p icmp --icmp-type source-quench -j DROP' "$file"
        fi
    else
        sed -i '/ufw-before-input.*-p icmpv6/s/-j ACCEPT/-j DROP/g' "$file"
        sed -i '/ufw-before-forward.*-p icmpv6/s/-j ACCEPT/-j DROP/g' "$file"
    fi
}

step_6_icmp_block() {
    msg "$(t STEP6_START)"

    local ok=true
    _block_icmp_in_file /etc/ufw/before.rules  "true"  || ok=false
    _block_icmp_in_file /etc/ufw/before6.rules "false" || ok=false

    if $ok; then
        ufw reload >> "$LOG_FILE" 2>&1 || true
        msg "$(t STEP6_OK)"
    else
        warn "$(t STEP6_FAIL)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7.1: SSL CERTIFICATE (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_7_1_ssl_cert() {
    msg "$(t SSL_START "$SERVER_IP")"

    # Ensure certbot >= 5.4 (needed for --preferred-profile shortlived and --ip-address)
    local certbot_ok=false
    if command -v certbot &>/dev/null; then
        local ver
        ver=$(certbot --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major minor
        major=$(printf '%s' "$ver" | cut -d. -f1)
        minor=$(printf '%s' "$ver" | cut -d. -f2)
        if (( major > 5 )) || (( major == 5 && minor >= 4 )); then
            certbot_ok=true
        fi
    fi

    if ! $certbot_ok; then
        log "INFO" "Installing certbot via pip3"
        if command -v pip3 &>/dev/null; then
            pip3 install --upgrade certbot >> "$LOG_FILE" 2>&1 && certbot_ok=true
        fi
        if ! $certbot_ok && command -v snap &>/dev/null; then
            snap install --classic certbot >> "$LOG_FILE" 2>&1 \
                && ln -sf /snap/bin/certbot /usr/local/bin/certbot 2>/dev/null || true
            certbot_ok=true
        fi
    fi

    if ! command -v certbot &>/dev/null; then
        warn "$(t SSL_FAIL)"
        return 1
    fi

    # IP certificates (--ip-address / --preferred-profile) are an experimental
    # Let's Encrypt feature; bail out fast instead of wasting a doomed attempt.
    local cb_help
    cb_help=$(certbot --help all 2>&1)
    if ! grep -q -- '--ip-address' <<< "$cb_help" || ! grep -q -- '--preferred-profile' <<< "$cb_help"; then
        log "WARN" "certbot does not support --ip-address/--preferred-profile flags"
        warn "$(t UNSUPPORTED_SKIP "certbot")"
        warn "$(t SSL_FAIL)"
        return 1
    fi

    certbot certonly \
        --preferred-profile shortlived \
        --standalone \
        --ip-address "$SERVER_IP" \
        --non-interactive \
        --agree-tos \
        --email admin@example.com \
        >> "$LOG_FILE" 2>&1 || {
            warn "$(t SSL_FAIL)"
            return 1
        }

    # Close port 80 after cert is issued
    ufw delete allow 80/tcp >> "$LOG_FILE" 2>&1 || true

    # Cron for auto-renewal every 5 days at 3am
    local cron_line="0 3 */5 * * certbot renew --quiet --standalone >> /var/log/certbot-renew.log 2>&1"
    ( crontab -l 2>/dev/null | grep -v certbot; printf '%s\n' "$cron_line" ) | crontab -

    PANEL_PROTO="https"
    SSL_CERT_ISSUED=true
    log "INFO" "SSL cert issued for $SERVER_IP, port 80 closed, cron added"
    msg "$(t SSL_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7.2: INSTALL 3X-UI (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

_find_xui_cmd() {
    local candidate
    for candidate in x-ui /usr/local/x-ui/x-ui; do
        if command -v "$candidate" &>/dev/null || [[ -x "$candidate" ]]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

step_7_2_install_3xui() {
    msg "$(t XUID_START)"

    local xui_cmd=""
    if xui_cmd=$(_find_xui_cmd); then
        msg "$(t ALREADY_INSTALLED "3x-ui")"
    else
        # Download installer to temp file
        if ! curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh \
             -o /tmp/3xui_install.sh >> "$LOG_FILE" 2>&1; then
            warn "$(t XUID_FAIL)"
            return 1
        fi
        chmod +x /tmp/3xui_install.sh

        # Automate interactive installer with expect
        if ! command -v expect &>/dev/null; then
            apt-get install -y expect >> "$LOG_FILE" 2>&1 || true
        fi

        # Generic catch-all: answer menu choices with "1", yes/no prompts with "y",
        # and any other prompt by just pressing Enter (accept default), until eof.
        expect -c "
            set timeout 300
            log_file -a \"${LOG_FILE}\"
            spawn bash /tmp/3xui_install.sh
            expect {
                -re {(Please choose|选择|choice|\\[1\\])} {
                    send \"1\r\"
                    exp_continue
                }
                -re {\\(y/n\\)|\\(Y/n\\)|\\(y/N\\)|y/N} {
                    send \"y\r\"
                    exp_continue
                }
                -re {:\\s*\$} {
                    send \"\r\"
                    exp_continue
                }
                eof
            }
            catch wait result
            exit [lindex \$result 3]
        " >> "$LOG_FILE" 2>&1

        rm -f /tmp/3xui_install.sh

        if ! xui_cmd=$(_find_xui_cmd); then
            warn "$(t XUID_FAIL)"
            return 1
        fi
    fi

    # Set credentials
    PANEL_USER=$(openssl rand -hex 4)
    PANEL_PASS=$(openssl rand -base64 12 | tr -d '=\n/')

    "$xui_cmd" setting -username "$PANEL_USER" -password "$PANEL_PASS" >> "$LOG_FILE" 2>&1 || true
    log "INFO" "3x-ui credentials set: user=$PANEL_USER pass=***"

    systemctl restart x-ui >> "$LOG_FILE" 2>&1 || true
    sleep 5

    # Verify the service actually came up; one retry before giving up
    if ! systemctl is-active --quiet x-ui; then
        log "WARN" "x-ui not active after restart, retrying once"
        systemctl restart x-ui >> "$LOG_FILE" 2>&1 || true
        sleep 5
        if ! systemctl is-active --quiet x-ui; then
            warn "$(t XUID_FAIL)"
            return 1
        fi
    fi

    msg "$(t XUID_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7.3: SNI SCAN (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_7_3_sni_scan() {
    msg "$(t SNI_START)"

    # Map architecture
    local arch
    case "$(uname -m)" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7*)  arch="armv7" ;;
        *)
            log "WARN" "Unknown arch $(uname -m), skipping SNI scan"
            msg "$(t SNI_FALLBACK "$VLESS_SNI")"
            return 1
            ;;
    esac

    # Get download URL from GitHub Releases API
    local release_url
    release_url=$(curl -s --max-time 15 \
        "https://api.github.com/repos/XTLS/RealiTLScanner/releases/latest" \
        | jq -r --arg arch "$arch" \
          '.assets[] | select(.name | ascii_downcase | test($arch)) | .browser_download_url' \
        2>/dev/null | head -1)

    if [[ -z "$release_url" ]]; then
        log "WARN" "RealiTLScanner release not found for arch=$arch"
        msg "$(t SNI_FALLBACK "$VLESS_SNI")"
        return 1
    fi

    local scanner="/tmp/RealiTLScanner"
    if ! curl -fsSL --max-time 30 "$release_url" -o "$scanner" >> "$LOG_FILE" 2>&1; then
        log "WARN" "Failed to download RealiTLScanner"
        msg "$(t SNI_FALLBACK "$VLESS_SNI")"
        return 1
    fi
    chmod +x "$scanner"

    local scan_out="/tmp/reality_scan.csv"
    timeout 60 "$scanner" -addr "$SERVER_IP" -thread 10 -out "$scan_out" \
        >> "$LOG_FILE" 2>&1 || true

    local found_sni=""
    if [[ -f "$scan_out" ]]; then
        found_sni=$(awk -F',' 'NR>1 && $1!="" {print $1; exit}' "$scan_out" 2>/dev/null)
    fi

    if [[ -n "$found_sni" ]]; then
        msg "$(t SNI_FOUND "$found_sni")"
        if [[ "$INSTALL_MODE" == "step" ]]; then
            printf '%b' "$(t SNI_PROMPT "$found_sni")"
            local sni_input
            read -r sni_input
            VLESS_SNI="${sni_input:-$found_sni}"
        else
            VLESS_SNI="$found_sni"
        fi
    else
        msg "$(t SNI_FALLBACK "$VLESS_SNI")"
    fi

    log "INFO" "VLESS SNI selected: $VLESS_SNI"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7.4: CREATE VLESS+REALITY INBOUND VIA 3X-UI API (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

step_7_4_create_inbound() {
    msg "$(t INBOUND_START)"

    if [[ -z "$PANEL_USER" || -z "$PANEL_PASS" ]]; then
        warn "$(t INBOUND_FAIL)"
        return 1
    fi

    local base_url="http://localhost:2053"
    local cookie_jar="/tmp/3xui_session.txt"

    # Login to get session cookie
    local login_resp
    login_resp=$(curl -s --max-time 15 \
        -c "$cookie_jar" \
        -X POST "${base_url}/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${PANEL_USER}&password=${PANEL_PASS}" 2>>"$LOG_FILE")

    local success
    success=$(printf '%s' "$login_resp" | jq -r '.success' 2>/dev/null)
    if [[ "$success" != "true" ]]; then
        log "WARN" "3x-ui API login failed"
        rm -f "$cookie_jar"
        warn "$(t INBOUND_FAIL)"
        return 1
    fi

    # Generate credentials
    VLESS_UUID=$(xray uuid 2>/dev/null || uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    local keypair
    keypair=$(xray x25519 2>/dev/null || true)

    if [[ -n "$keypair" ]]; then
        VLESS_PUBLIC_KEY=$(printf '%s' "$keypair" | grep -i 'public' | awk '{print $NF}')
        VLESS_PRIVATE_KEY=$(printf '%s' "$keypair" | grep -i 'private' | awk '{print $NF}')
    else
        # Fallback: generate via openssl if xray x25519 not available
        VLESS_PRIVATE_KEY=$(openssl genpkey -algorithm X25519 2>/dev/null \
            | openssl pkey -pubout 2>/dev/null | tail -1 || openssl rand -hex 32)
        VLESS_PUBLIC_KEY=$(openssl rand -hex 32)
    fi

    VLESS_SHORT_ID=$(openssl rand -hex 8)

    # Build inbound JSON (settings & streamSettings must be JSON strings)
    local settings_obj stream_obj
    settings_obj=$(jq -n \
        --arg uuid "$VLESS_UUID" \
        '{"clients":[{"id":$uuid,"flow":"xtls-rprx-vision","email":"user@vpn","enable":true}],"decryption":"none","fallbacks":[]}')

    stream_obj=$(jq -n \
        --arg sni "$VLESS_SNI" \
        --arg pbk "$VLESS_PUBLIC_KEY" \
        --arg pvk "$VLESS_PRIVATE_KEY" \
        --arg sid "$VLESS_SHORT_ID" \
        '{
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": false,
                "dest": ($sni + ":443"),
                "xver": 0,
                "serverNames": [$sni],
                "privateKey": $pvk,
                "minClientVer": "",
                "maxClientVer": "",
                "maxTimeDiff": 0,
                "shortIds": [$sid]
            },
            "tcpSettings": {"header": {"type": "none"}},
            "fingerprint": "chrome"
        }')

    local payload
    payload=$(jq -n \
        --argjson settings "$settings_obj" \
        --argjson stream "$stream_obj" \
        '{
            "remark": "vless-reality",
            "enable": true,
            "protocol": "vless",
            "port": 443,
            "expiryTime": 0,
            "listen": "",
            "settings": ($settings | tostring),
            "streamSettings": ($stream | tostring),
            "sniffing": {"enabled": false, "destOverride": []}
        }')

    local add_resp
    add_resp=$(curl -s --max-time 15 \
        -b "$cookie_jar" \
        -X POST "${base_url}/xui/API/inbounds/add" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>>"$LOG_FILE")

    rm -f "$cookie_jar"

    if [[ "$(printf '%s' "$add_resp" | jq -r '.success' 2>/dev/null)" != "true" ]]; then
        log "WARN" "Failed to add inbound: $(printf '%s' "$add_resp" | jq -r '.msg' 2>/dev/null)"
        warn "$(t INBOUND_FAIL)"
        return 1
    fi

    VLESS_LINK="vless://${VLESS_UUID}@${SERVER_IP}:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${VLESS_SNI}&fp=chrome&pbk=${VLESS_PUBLIC_KEY}&sid=${VLESS_SHORT_ID}&type=tcp#MyVPN"
    log "INFO" "VLESS+Reality inbound created, SNI=$VLESS_SNI"
    msg "$(t INBOUND_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8: TELEMT (NON-CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────

_find_telemt_config() {
    local p config_file=""
    for p in /etc/telemt/config.toml \
              /opt/telemt/config.toml \
              /usr/local/etc/telemt/config.toml \
              "$HOME/.config/telemt/config.toml"; do
        if [[ -f "$p" ]]; then
            printf '%s' "$p"
            return 0
        fi
    done
    config_file=$(find /etc /opt /usr/local -name "config.toml" \
        -path "*/telemt/*" 2>/dev/null | head -1)
    if [[ -n "$config_file" ]]; then
        printf '%s' "$config_file"
        return 0
    fi
    return 1
}

step_8_telemt() {
    msg "$(t STEP8_START)"

    # TELEMT_PORT was gathered in step_0 for step mode; already in UFW from step_4

    local install_url="https://raw.githubusercontent.com/telemt/telemt/main/install.sh"
    local config_file=""

    if config_file=$(_find_telemt_config); then
        msg "$(t ALREADY_INSTALLED "telemt")"
    else
        if ! curl -fsSL --head --max-time 10 "$install_url" >> "$LOG_FILE" 2>&1; then
            log "WARN" "telemt install script unreachable: $install_url"
            warn "$(t UNREACHABLE_SKIP "telemt")"
            TELEMT_LINK=""
            return 1
        fi

        if ! curl -fsSL --max-time 60 "$install_url" | sh >> "$LOG_FILE" 2>&1; then
            warn "$(t STEP8_FAIL)"
            TELEMT_LINK=""
            return 1
        fi

        if ! config_file=$(_find_telemt_config); then
            log "WARN" "telemt config not found after install"
            TELEMT_LINK=""
            return 1
        fi
    fi

    if [[ -z "$config_file" ]]; then
        log "WARN" "telemt config not found"
        TELEMT_LINK=""
        return 1
    fi

    TELEMT_SECRET=$(grep -E '^\s*secret\s*=' "$config_file" 2>/dev/null \
        | head -1 \
        | sed "s/.*=\s*[\"']\?\([^\"']*\)[\"']\?.*/\1/" \
        | tr -d '[:space:]')

    if [[ -z "$TELEMT_SECRET" ]]; then
        log "WARN" "Could not extract telemt secret from $config_file"
        TELEMT_LINK=""
        return 1
    fi

    TELEMT_LINK="tg://proxy?server=${SERVER_IP}&port=${TELEMT_PORT}&secret=${TELEMT_SECRET}"
    log "INFO" "telemt configured on port $TELEMT_PORT"
    msg "$(t STEP8_OK)"
}

# ─────────────────────────────────────────────────────────────────────────────
# PRINT SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

print_summary() {
    local W=52
    local hr
    hr=$(printf '═%.0s' $(seq 1 $W))

    # Build output
    local out=""
    out+=$(printf '╔%s╗\n' "$hr")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_TITLE)")
    out+=$(printf '╠%s╣\n' "$hr")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_SSH): ${SSH_PORT}")
    out+=$(printf '║  %-48s  ║\n' "")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_PANEL_TITLE)")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_PANEL_URL): ${PANEL_PROTO}://${SERVER_IP}:2053")

    if [[ -n "$PANEL_USER" ]]; then
        out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_PANEL_USER): ${PANEL_USER}")
        out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_PANEL_PASS): ${PANEL_PASS}")
    fi

    out+=$(printf '║  %-48s  ║\n' "")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_VLESS_TITLE)")

    if [[ -n "$VLESS_LINK" ]]; then
        # Print link in chunks of 48 chars
        local link="$VLESS_LINK"
        while [[ ${#link} -gt 0 ]]; do
            out+=$(printf '║  %-48s  ║\n' "${link:0:48}")
            link="${link:48}"
        done
    else
        out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_NO_VLESS)")
    fi

    out+=$(printf '║  %-48s  ║\n' "")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_TG_TITLE)")

    if [[ -n "$TELEMT_LINK" ]]; then
        local tlink="$TELEMT_LINK"
        while [[ ${#tlink} -gt 0 ]]; do
            out+=$(printf '║  %-48s  ║\n' "${tlink:0:48}")
            tlink="${tlink:48}"
        done
    else
        out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_NO_TG)")
    fi

    out+=$(printf '║  %-48s  ║\n' "")

    if $SSL_CERT_ISSUED; then
        out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_SSL_INFO)")
    else
        out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_NO_SSL)")
    fi

    out+=$(printf '║  %-48s  ║\n' "")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_SECURITY_TITLE)")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_SECURITY_TEXT1)")
    out+=$(printf '║  %-48s  ║\n' "$(t SUMMARY_SECURITY_TEXT2)")

    out+=$(printf '╚%s╝\n' "$hr")
    out+=$(printf '  %s\n' "$(t SUMMARY_SAVED "$CREDS_FILE")")

    printf '\n%s\n' "$out"

    # Save to credentials file with restricted permissions
    install -m 600 /dev/null "$CREDS_FILE"
    printf '%s\n' "$out" > "$CREDS_FILE"
    log "INFO" "Credentials saved to $CREDS_FILE"
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

main() {
    # Must be root
    if [[ "$(id -u)" -ne 0 ]]; then
        printf '%s\n' "$(t ERR_NOT_ROOT)" >&2
        exit 1
    fi

    # Initialize log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    log "INFO" "=== VPN Server Setup started ==="

    # Detect server IP early
    SERVER_IP=$(curl -4 -s --max-time 10 ifconfig.me 2>/dev/null \
        || curl -4 -s --max-time 10 api.ipify.org 2>/dev/null \
        || hostname -I 2>/dev/null | awk '{print $1}')
    log "INFO" "Server IP: ${SERVER_IP:-unknown}"

    step_0_language

    install_dependencies

    run_critical "System Update" step_1_system_update

    step_2_ssh_port
    step_3_root_password

    run_critical "UFW Firewall" step_4_ufw

    run_safe "fail2ban"     step_5_fail2ban
    run_safe "ICMP blocking" step_6_icmp_block

    msg "$(t STEP7_START)"
    run_safe "SSL certificate"      step_7_1_ssl_cert
    run_safe "3x-ui installation"   step_7_2_install_3xui
    run_safe "SNI scan"             step_7_3_sni_scan
    run_safe "VLESS inbound create" step_7_4_create_inbound

    run_safe "telemt installation"  step_8_telemt

    print_summary

    log "INFO" "=== VPN Server Setup completed ==="
}

main "$@"
