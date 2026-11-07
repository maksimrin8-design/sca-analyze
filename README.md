# SCA Analyze: OSV-Scanner vs Grype

Бенчмарк для сравнения **OSV-Scanner** и **Grype** на зависимостях реальных GitHub-проектов.

## Область исследования

Проект охватывает только **SCA (Software Composition Analysis)** — обнаружение известных уязвимостей в сторонних зависимостях. SAST, Secret Scanning и SBOM как отдельные эксперименты не входят в текущий объём.

## Структура

- `projects/manifest.json` — 30 upstream GitHub-репозиториев с закреплёнными commit SHA.
- `.github/workflows/scan.yml` — запуск OSV-Scanner и Grype.
- `ground-truth/expected-vulnerabilities.csv` — проверяемый эталон; оцениваются только записи со статусом `verified`.
- `scripts/build_sca_table.py` — формирует одну сравнительную таблицу SCA.

Для каждого приложения workflow создаёт `osv/`, `grype/` и `default/`. Результаты сохраняются как GitHub Actions artifacts, а не коммитятся в репозиторий.

## Запуск

1. Откройте **Actions → SCA benchmark (OSV-Scanner vs Grype)**.
2. Нажмите **Run workflow**.
3. Скачайте per-project artifacts `scan-Pxxx-...`.
4. Скачайте `sca-benchmark-comparison`: в нём будут `sca-comparison.md`, `sca-comparison.csv` и `evidence-index.json`.

## Ground Truth и ограничения

Наличие проекта в корпусе не означает, что все его зависимости уязвимы. Пустой эталон означает «не проверено», а не «уязвимостей нет». Неизвестные находки не объявляются ложноположительными.

Сейчас подтверждён один тестовый случай: `coder/osv-test`, `minimist@0.0.8`, npm, `GHSA-xvch-5gv4-984h` / `CVE-2021-44906`. Остальные проекты требуют проверки lockfiles и затронутых диапазонов версий.

## Воспроизводимость

Workflow сохраняет фактический upstream commit и версии сканеров в артефактах. Для финального эксперимента рекомендуется закрепить версии OSV-Scanner и Grype, а также фиксировать дату/состояние баз уязвимостей.
