# Запуск (без docker, только Python 3.10+, без pip-зависимостей)
    python -m aegis init
    python -m aegis check
    python -m aegis org MyOrg
    python -m aegis seed MyOrg domain example.com            # CANDIDATE
    python -m aegis probe 1                                   # должно быть ОТКЛОНЕНО
    python -m aegis seed MyOrg domain mydomain.com --verified # только своё!
    python -m unittest discover tests
Ollama (опционально): установить нативно с ollama.com, `ollama pull llama3.2:3b`.

## Регулярный запуск (без docker)
Один раз: `python -m aegis scan MyOrg` (run + web + diff + дайджест).
По расписанию, вариант 1 (cron, каждые 6 ч): `crontab -e` и строка
`0 */6 * * * cd ~/AI/AEGIS-main/AEGIS-main && python -m aegis scan MyOrg --no-llm >> data/cron.log 2>&1`
Вариант 2 (в терминале/tmux): `python -m aegis watch MyOrg --every 6`
