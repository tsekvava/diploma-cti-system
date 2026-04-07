#!/usr/bin/env python3
"""
CTI Pipeline — Web UI (Streamlit).

Запуск:
    streamlit run web_ui.py

Страницы:
    1. Анализ отчёта — загрузка файла или вставка текста, 7-этапный пайплайн
    2. MITRE Enrichment — обогащение запросов из MITRE ATT&CK
    3. Профиль APT/ПО — генерация профиля группы или ПО
    4. Бенчмарк — графики и таблицы результатов
"""

import json
import os
import sys
import time
from pathlib import Path

import streamlit as st
import pandas as pd

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# ─── Конфигурация страницы ───────────────────────────────────────────────────

st.set_page_config(
    page_title="CTI Pipeline",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Sidebar: навигация ─────────────────────────────────────────────────────

st.sidebar.title("CTI Pipeline")
st.sidebar.caption("Автоматизированный анализ киберугроз")

page = st.sidebar.radio(
    "Навигация",
    ["Анализ отчёта", "MITRE Enrichment", "Профиль APT/ПО", "Бенчмарк"],
)

# Настройки модели (общие)
st.sidebar.markdown("---")
st.sidebar.subheader("Настройки")
ollama_model = st.sidebar.text_input("Ollama модель", value="gemma2:9b")
ollama_host = st.sidebar.text_input("Ollama хост", value=os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434"))

# RAG toggle
use_rag = st.sidebar.checkbox("RAG (поиск похожих отчётов)", value=False)


# ─── Вспомогательные функции ─────────────────────────────────────────────────

@st.cache_resource
def get_enricher():
    from knowledge_base.query_enricher import QueryEnricher
    return QueryEnricher()


def set_ollama_env(host):
    """Устанавливает переменную окружения для Ollama."""
    os.environ["OLLAMA_HOST"] = host


# ─── Страница 1: Анализ отчёта ──────────────────────────────────────────────

def page_analyze():
    st.header("Анализ отчёта")
    st.markdown("Загрузите файл или вставьте текст для 7-этапного анализа.")

    col1, col2 = st.columns([2, 1])

    with col1:
        input_method = st.radio("Способ ввода", ["Текст", "Файл"], horizontal=True)

        text = ""
        source = "web-ui"
        input_metadata = {
            "input_format": "text",
            "pages": 1,
            "ocr_used": False,
            "parse_warnings": [],
        }

        if input_method == "Текст":
            text = st.text_area(
                "Текст отчёта",
                height=300,
                placeholder="Вставьте текст CTI-отчёта здесь...",
            )
        else:
            uploaded = st.file_uploader(
                "Загрузите файл",
                type=["txt", "md", "log", "html", "pdf", "docx"],
            )
            if uploaded:
                # Сохраняем во временный файл для input_loader
                import tempfile
                suffix = Path(uploaded.name).suffix
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(uploaded.read())
                    tmp_path = tmp.name

                try:
                    from summarizer.input_loader import load_report_file
                    loaded = load_report_file(tmp_path)
                    text = loaded.text
                    source = uploaded.name
                    input_metadata = {
                        "input_format": loaded.input_format,
                        "pages": loaded.pages,
                        "ocr_used": loaded.ocr_used,
                        "parse_warnings": loaded.parse_warnings,
                    }
                    st.success(f"Загружен: {uploaded.name} ({loaded.input_format}, {len(text)} симв.)")
                except Exception as e:
                    st.error(f"Ошибка парсинга: {e}")
                finally:
                    os.unlink(tmp_path)

    with col2:
        st.markdown("**Параметры**")
        export_stix = st.checkbox("Экспорт STIX Bundle")
        tlp = st.selectbox("TLP", ["TLP:AMBER", "TLP:WHITE", "TLP:GREEN", "TLP:RED"])

    if st.button("Запустить анализ", type="primary", disabled=not text.strip()):
        set_ollama_env(ollama_host)

        from summarizer.report_summarizer import ReportSummarizer

        # RAG context
        rag_context = ""
        if use_rag:
            try:
                from rag_engine import RAGSystem
                rag = RAGSystem()
                if rag.count > 0:
                    rag_context = rag.build_context(text)
                    if rag_context:
                        st.info(f"RAG: найден контекст из {rag.count} отчётов")
            except ImportError:
                st.warning("RAG недоступен (chromadb не установлен)")

        summarizer = ReportSummarizer(model_name=ollama_model)

        progress = st.progress(0, text="Запуск пайплайна...")
        status = st.empty()

        start_time = time.time()
        stages = [
            "1/7 Regex IoC экстракция",
            "2/7 LLM экстракция сущностей",
            "3/7 Нормализация MITRE ATT&CK",
            "4/7 Kill Chain маппинг",
            "5/7 Confidence scoring",
            "6/7 Генерация summary",
            "7/7 Перевод и форматирование",
        ]

        # Запуск анализа (процесс синхронный, прогресс обновляем по завершении)
        for i, stage_name in enumerate(stages):
            progress.progress((i) / 7, text=stage_name)

        try:
            result = summarizer.process(
                text, source=source,
                input_metadata=input_metadata,
                rag_context=rag_context,
            )
        except Exception as e:
            st.error(f"Ошибка анализа: {e}")
            return

        elapsed = time.time() - start_time
        progress.progress(1.0, text="Готово!")
        status.success(f"Анализ завершён за {elapsed:.1f} секунд")

        # RAG: index after analysis
        if use_rag:
            try:
                from rag_engine import RAGSystem
                rag = RAGSystem()
                rag.index_report(text, result, source=source)
            except Exception:
                pass

        # ── Отображение результатов ──
        st.markdown("---")
        _display_analysis_result(result, export_stix, tlp)


def _display_analysis_result(result, export_stix=False, tlp="TLP:AMBER"):
    """Отображение результатов анализа."""
    data = result.get("json", {})

    # Табы для секций
    tab_summary, tab_actors, tab_ioc, tab_killchain, tab_json = st.tabs([
        "Аналитическая записка",
        "Акторы и ПО",
        "Индикаторы (IoC)",
        "Kill Chain",
        "JSON",
    ])

    with tab_summary:
        note = result.get("note_ru", "")
        if note:
            st.markdown(note)
        else:
            summary = result.get("summary_en", "")
            if summary:
                st.markdown(summary)

        # Метаданные
        meta = data.get("metadata", {})
        if meta:
            cols = st.columns(4)
            cols[0].metric("Модель", meta.get("model", "?"))
            cols[1].metric("Время", f"{meta.get('processing_time_sec', 0):.1f}с")
            cols[2].metric("Формат", meta.get("input_format", "?"))
            cols[3].metric("Confidence", f"{data.get('overall_confidence', '?')}%")

    with tab_actors:
        col_a, col_b = st.columns(2)

        with col_a:
            st.subheader("Threat Actors")
            actors = data.get("threat_actors", [])
            if actors:
                for a in actors:
                    name = a.get("name", "?")
                    mid = a.get("mitre_id", "")
                    conf = a.get("confidence", 0)
                    tag = f"🟢" if conf >= 70 else f"🟡" if conf >= 40 else f"🔴"
                    st.markdown(f"{tag} **{name}** {f'({mid})' if mid else ''} — confidence: {conf}%")
                    if a.get("aliases"):
                        st.caption(f"Aliases: {', '.join(a['aliases'][:5])}")
            else:
                st.info("Не обнаружены")

        with col_b:
            st.subheader("Malware / Tools")
            for section, items in [("Malware", data.get("malware", [])), ("Tools", data.get("tools", []))]:
                if items:
                    st.markdown(f"**{section}:**")
                    for m in items:
                        name = m.get("name", "?")
                        mid = m.get("mitre_id", "")
                        conf = m.get("confidence", 0)
                        st.markdown(f"- **{name}** {f'({mid})' if mid else ''} — {conf}%")

        # Targeted countries
        countries = data.get("targeted_countries", [])
        if countries:
            st.subheader("Целевые страны")
            st.markdown(", ".join(countries))

    with tab_ioc:
        indicators = data.get("indicators", {})
        vulns = data.get("vulnerabilities", [])

        if vulns:
            st.subheader("Уязвимости (CVE)")
            for v in vulns:
                st.markdown(f"- **{v.get('id', '?')}** — confidence: {v.get('confidence', 0)}%")

        for ioc_type, label in [("ipv4", "IP-адреса"), ("domain", "Домены"), ("hash", "Хеши"), ("email", "Email")]:
            items = indicators.get(ioc_type, [])
            if items:
                st.subheader(f"{label} ({len(items)})")
                # Показываем как код-блок для удобного копирования
                st.code("\n".join(items), language=None)

    with tab_killchain:
        kill_chain = data.get("kill_chain", [])
        if kill_chain:
            for phase in kill_chain:
                tactic = phase.get("tactic_name_en", phase.get("tactic_id", "?"))
                tactic_ru = phase.get("tactic_name_ru", "")
                techs = phase.get("techniques", [])

                with st.expander(f"**{tactic}** {f'({tactic_ru})' if tactic_ru else ''} — {len(techs)} technique(s)", expanded=True):
                    for t in techs:
                        tid = t.get("id", "?")
                        tname = t.get("name_en", "?")
                        conf = t.get("confidence", 0)
                        validated = "✓" if t.get("validated") else ""
                        evidence = t.get("evidence", "")
                        st.markdown(f"- **{tid}** {tname} — {conf}% {validated}")
                        if evidence:
                            st.caption(f"Evidence: {evidence[:200]}")
        else:
            st.info("Kill Chain не сформирован")

    with tab_json:
        st.json(data)
        # Кнопка скачивания
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        st.download_button(
            "Скачать JSON",
            data=json_str,
            file_name="cti_analysis.json",
            mime="application/json",
        )

    # STIX Export
    if export_stix:
        st.markdown("---")
        st.subheader("STIX 2.1 Bundle")
        try:
            from opencti_exporter import OpenCTIExporter
            exporter = OpenCTIExporter(tlp=tlp, dry_run=True)
            bundle = exporter.export_stix_bundle(data)
            if bundle:
                bundle_str = json.dumps(bundle, indent=2, ensure_ascii=False)
                st.json(bundle)
                st.download_button(
                    "Скачать STIX Bundle",
                    data=bundle_str,
                    file_name="stix_bundle.json",
                    mime="application/json",
                )
        except Exception as e:
            st.error(f"Ошибка STIX экспорта: {e}")


# ─── Страница 2: MITRE Enrichment ───────────────────────────────────────────

def page_enrich():
    st.header("MITRE ATT&CK Enrichment")
    st.markdown("Обогащение запросов из локальной базы MITRE ATT&CK (634 техники, 172 группы, 784 ПО).")

    query = st.text_input(
        "Запрос",
        placeholder="T1059, G0032, APT28, Cobalt Strike, CVE-2024-38063...",
    )

    col1, col2 = st.columns([1, 4])
    with col1:
        json_mode = st.checkbox("JSON вывод")

    if query and st.button("Обогатить", type="primary"):
        enricher = get_enricher()

        try:
            result = enricher.enrich(query)
        except Exception as e:
            st.error(f"Ошибка: {e}")
            return

        # Detected
        detected = result.get("detected", [])
        if detected:
            st.success(f"Найдено: {', '.join(d.get('name', d.get('id', '?')) for d in detected)}")
        else:
            st.warning("Не удалось определить тип запроса")
            return

        if json_mode:
            st.json(result)
            return

        # Enrichments
        enrichments = result.get("enrichments", [])
        for enr in enrichments:
            _display_enrichment(enr)

        # LLM context
        ctx = result.get("context_for_llm", "")
        if ctx:
            with st.expander("Контекст для LLM"):
                st.text(ctx)


def _display_enrichment(enr):
    """Отображение одного обогащения."""
    eid = enr.get("id", "?")
    ename = enr.get("name", enr.get("name_en", "?"))

    st.subheader(f"{eid} — {ename}")

    # Technique
    if "tactic_id" in enr:
        cols = st.columns(3)
        cols[0].markdown(f"**Тактика:** {enr.get('tactic_id', '?')}")
        name_ru = enr.get("name_ru", "")
        if name_ru:
            cols[1].markdown(f"**RU:** {name_ru}")

        subs = enr.get("subtechniques", [])
        if subs:
            st.markdown(f"**Подтехники ({len(subs)}):**")
            for s in subs:
                if isinstance(s, dict):
                    st.markdown(f"- {s.get('id', '?')} {s.get('name', '')}")
                else:
                    st.markdown(f"- {s}")

        groups = enr.get("used_by_groups", [])
        if groups:
            with st.expander(f"Используется группами ({len(groups)})"):
                for g in groups:
                    if isinstance(g, dict):
                        st.markdown(f"- {g.get('id', '?')} {g.get('name', '')}")
                    else:
                        st.markdown(f"- {g}")

        mitigations = enr.get("mitigations", [])
        if mitigations:
            with st.expander(f"Меры противодействия ({len(mitigations)})"):
                for m in mitigations:
                    if isinstance(m, dict):
                        st.markdown(f"- {m.get('id', '?')} {m.get('name', '')}")
                    else:
                        st.markdown(f"- {m}")

    # Group
    if "aliases" in enr and "techniques" in enr:
        cols = st.columns(3)
        aliases = enr.get("aliases", [])
        country = enr.get("country", "")
        techs = enr.get("techniques", [])
        sw = enr.get("software", [])

        if aliases:
            cols[0].markdown(f"**Aliases:** {', '.join(aliases[:10])}")
        if country:
            cols[1].markdown(f"**Страна:** {country}")
        cols[2].markdown(f"**Техники:** {len(techs)} | **ПО:** {len(sw)}")

        if techs:
            with st.expander(f"Техники ({len(techs)})"):
                for t in techs[:30]:
                    if isinstance(t, dict):
                        st.markdown(f"- {t.get('id', '?')} {t.get('name', '')}")
                    else:
                        st.markdown(f"- {t}")

        if sw:
            with st.expander(f"ПО ({len(sw)})"):
                for s in sw[:20]:
                    if isinstance(s, dict):
                        st.markdown(f"- {s.get('id', '?')} {s.get('name', '')}")
                    else:
                        st.markdown(f"- {s}")

    # Software
    if "software_type" in enr:
        st.markdown(f"**Тип:** {enr.get('software_type', '?')}")
        aliases = enr.get("aliases", [])
        if aliases:
            st.markdown(f"**Aliases:** {', '.join(aliases[:10])}")

        groups = enr.get("used_by_groups", [])
        if groups:
            with st.expander(f"Используется группами ({len(groups)})"):
                for g in groups[:20]:
                    if isinstance(g, dict):
                        st.markdown(f"- {g.get('id', '?')} {g.get('name', '')}")
                    else:
                        st.markdown(f"- {g}")


# ─── Страница 3: Профиль APT/ПО ────────────────────────────────────────────

def page_profile():
    st.header("Профиль APT-группы / ПО")
    st.markdown("LLM-генерация профиля на основе данных MITRE ATT&CK.")

    query = st.text_input(
        "Группа или ПО",
        placeholder="APT28, G0032, Lazarus Group, Cobalt Strike, Mimikatz...",
    )

    if query and st.button("Сгенерировать профиль", type="primary"):
        set_ollama_env(ollama_host)

        from summarizer.profiler import Profiler

        with st.spinner("Генерация профиля (LLM)..."):
            try:
                profiler = Profiler(model_name=ollama_model)
                result = profiler.profile(query)
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return

        if not result:
            st.warning("Не удалось создать профиль")
            return

        # Метаданные
        entity_type = result.get("entity_type", "?")
        entity_name = result.get("entity_name", query)
        entity_id = result.get("entity_id", "")

        st.subheader(f"{entity_name} {f'({entity_id})' if entity_id else ''}")

        cols = st.columns(4)
        cols[0].metric("Тип", entity_type)
        if entity_type == "group":
            cols[1].metric("Техники", result.get("techniques_count", 0))
            cols[2].metric("ПО", result.get("software_count", 0))
            country = result.get("country", "")
            if country:
                cols[3].metric("Страна", country)
        elif entity_type == "software":
            cols[1].metric("Техники", result.get("techniques_count", 0))
            cols[2].metric("Группы", result.get("used_by_groups_count", 0))
            cols[3].metric("Тип ПО", result.get("software_type", "?"))

        aliases = result.get("aliases", [])
        if aliases:
            st.markdown(f"**Aliases:** {', '.join(aliases)}")

        # Профиль
        tab_ru, tab_en, tab_json = st.tabs(["Профиль (RU)", "Profile (EN)", "JSON"])

        with tab_ru:
            profile_ru = result.get("profile_ru", "")
            if profile_ru:
                st.markdown(profile_ru)
            else:
                st.info("Профиль на русском не сгенерирован")

        with tab_en:
            profile_en = result.get("profile_en", "")
            if profile_en:
                st.markdown(profile_en)
            else:
                st.info("English profile not generated")

        with tab_json:
            st.json(result)


# ─── Страница 4: Бенчмарк ──────────────────────────────────────────────────

def page_benchmark():
    st.header("Результаты бенчмарка")
    st.markdown("Сравнение 9 моделей на задаче извлечения CTI-сущностей.")

    charts_dir = ROOT / "benchmark" / "charts"

    # Сводная таблица
    summary_csv = ROOT / "benchmark" / "benchmark_full_9models_summary.csv"
    if summary_csv.exists():
        st.subheader("Сводная таблица")
        df = pd.read_csv(summary_csv)
        st.dataframe(df, use_container_width=True, hide_index=True)

    # Графики
    st.subheader("Графики")

    chart_files = [
        ("01_f1_overall.png", "F1-score по моделям"),
        ("02_f1_by_category.png", "F1-score по категориям"),
        ("03_precision_recall.png", "Precision vs Recall"),
        ("07_tp_fp_fn_by_model.png", "TP / FP / FN по моделям"),
        ("09_category_heatmap.png", "F1 Heatmap: модели x категории"),
        ("10_fp_fn_rates.png", "FP/FN rate по моделям"),
        ("05_heatmap.png", "Heatmap метрик"),
        ("06_radar_top3.png", "Radar: топ-3 модели"),
        ("04_time_comparison.png", "Время инференса"),
        ("08_tp_fp_fn_by_category.png", "TP/FP/FN по категориям"),
    ]

    # По 2 графика в ряд
    for i in range(0, len(chart_files), 2):
        cols = st.columns(2)
        for j, col in enumerate(cols):
            idx = i + j
            if idx < len(chart_files):
                fname, title = chart_files[idx]
                fpath = charts_dir / fname
                if fpath.exists():
                    with col:
                        st.markdown(f"**{title}**")
                        st.image(str(fpath), use_container_width=True)

    # Error Analysis
    st.markdown("---")
    st.subheader("Анализ ошибок")

    col1, col2 = st.columns(2)

    fp_csv = charts_dir / "top_false_positives.csv"
    fn_csv = charts_dir / "top_false_negatives.csv"

    with col1:
        if fp_csv.exists():
            st.markdown("**Топ ложных срабатываний (FP)**")
            df_fp = pd.read_csv(fp_csv)
            st.dataframe(df_fp.head(15), use_container_width=True, hide_index=True)

    with col2:
        if fn_csv.exists():
            st.markdown("**Топ пропусков (FN)**")
            df_fn = pd.read_csv(fn_csv)
            st.dataframe(df_fn.head(15), use_container_width=True, hide_index=True)

    # Hallucination rates
    hall_csv = charts_dir / "hallucination_rates.csv"
    if hall_csv.exists():
        st.subheader("Галлюцинации MITRE T-кодов")
        df_hall = pd.read_csv(hall_csv)
        st.dataframe(df_hall, use_container_width=True, hide_index=True)

    # Полная таблица
    error_csv = charts_dir / "error_analysis_summary.csv"
    if error_csv.exists():
        with st.expander("Полная таблица TP/FP/FN/P/R/F1 по моделям"):
            df_err = pd.read_csv(error_csv)
            st.dataframe(df_err, use_container_width=True, hide_index=True)


# ─── Роутинг ────────────────────────────────────────────────────────────────

if page == "Анализ отчёта":
    page_analyze()
elif page == "MITRE Enrichment":
    page_enrich()
elif page == "Профиль APT/ПО":
    page_profile()
elif page == "Бенчмарк":
    page_benchmark()
