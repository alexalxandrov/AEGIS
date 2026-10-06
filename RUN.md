# Запуск (без docker, только Python 3.10+, без pip-зависимостей)
    python -m aegis init
    python -m aegis check
    python -m aegis org MyOrg
    python -m aegis seed MyOrg domain example.com            # CANDIDATE
    python -m aegis probe 1                                   # должно быть ОТКЛОНЕНО
    python -m aegis seed MyOrg domain mydomain.com --verified # только своё!
    python -m unittest discover tests
Ollama (опционально): установить нативно с ollama.com, `ollama pull llama3.2:3b`.
