STRINGS = {
    "must_be_root": "shroud должен запускаться от root.",
    "lang_prompt": "Select language / Выберите язык: [1] English  [2] Русский: ",
    "mode_quick": "Быстрый режим: применяю значения по умолчанию без вопросов.",
    "mode_interactive": "Пошаговый режим: подтверждайте каждый шаг (Enter — принять значение по умолчанию).",
    "prompt_default": "%s [%s]: ",

    "phase.start": "=== Фаза %s: %s ===",
    "phase.preflight": "Предварительные проверки",
    "phase.hardening": "Хардненинг хоста",
    "phase.firewall": "Файрвол",
    "phase.certs": "Сертификат панели",
    "phase.stack": "Прокси-стек",
    "phase.cascade": "Каскад",
    "phase.verify": "Верификация / самотест",
    "phase.output": "Итог",

    "step.ok_already": "[ок] %s — уже в нужном состоянии",
    "step.applied": "[изменено] %s — применено",
    "step.verify_fail": "[ошибка] %s — verify() не прошёл после apply()",
    "step.skip_dry": "[dry-run] %s — было бы применено",
    "step.critical_abort": "Критический шаг «%s» не выполнен. Безопасная остановка; состояние сохранено.",
    "step.noncritical_warn": "Некритический шаг «%s» не выполнен; продолжаю с частичным результатом.",

    "preflight.os_unsupported": "Неподдерживаемая ОС: %s. shroud поддерживает Ubuntu 22.04/24.04.",
    "preflight.no_network": "Нет сетевой доступности до %s.",
    "preflight.ip_detected": "Публичный IP: %s (ASN: %s, %s)",
    "preflight.asn_throttle": (
        "ВНИМАНИЕ: провайдер «%s» (ASN %s) известен троттлингом/обрывом трафика "
        "обхода блокировок (поведение «~16 КБ и сброс»). Нода всё равно установится, "
        "но рекомендуется менее «засвеченный» регион/провайдер."),
    "preflight.strict_abort": "Остановка из-за --strict на троттлящемся ASN.",

    "ssh.warn_session": "ВНИМАНИЕ: не закрывайте текущую SSH-сессию, пока не проверите новый порт.",
    "ssh.port_kept": "SSH-порт не изменён (%s).",
    "ssh.port_changed": "SSH-порт изменён на %s (старый порт открыт до проверки).",
    "ssh.selftest_ok": "Новый SSH-порт %s доступен; старый порт можно закрыть.",
    "ssh.selftest_fail": "Новый SSH-порт %s НЕ доступен — откат на %s.",

    "sni.scanning": "Сканирую подсеть сервера в поиске Reality-донора того же ASN...",
    "sni.found": "Выбран Reality-донор SNI: %s",
    "sni.fallback": "Скан SNI безрезультатен; беру запасной донор того же ASN: %s",

    "output.saved": "Учётные данные записаны в %s (режим 0600).",
    "summary.title": "SHROUD — ИТОГ УСТАНОВКИ",

    "verify.pass": "[пройдено] %s",
    "verify.fail": "[ошибка] %s",
    "verify.note": "Верификация информативна; ошибки помечаются, но не фатальны.",
}
