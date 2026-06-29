import streamlit as st
import pandas as pd
import numpy as np
import joblib
import json
import plotly.express as px
import plotly.graph_objects as go
from streamlit_option_menu import option_menu

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberRisk — Insider Threat",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Space+Grotesk:wght@400;600;700&display=swap');
@import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

/* ── Background ── */
.stApp { background: #070b14; color: #cdd6f4; }
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0d1117 0%, #0a0f1a 100%);
    border-right: 1px solid #1a2744;
}

/* ── Hide default Streamlit elements ── */
#MainMenu, footer, header { visibility: hidden; }

/* ── Sidebar branding ── */
.brand-title {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 1.4rem; font-weight: 700;
    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: 1px; padding: 0.3rem 0;
}
.brand-sub { font-size: 0.72rem; color: #4a5568; letter-spacing: 2px; text-transform: uppercase; }

/* ── Section titles ── */
.section-title {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem;
    background: linear-gradient(90deg, #4facfe 0%, #00f2fe 60%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.section-sub { font-size: 0.85rem; color: #6b7a99; margin-bottom: 1.5rem; }

/* ── KPI cards ── */
.kpi-card {
    background: linear-gradient(135deg, #0d1b2a 0%, #0f2038 100%);
    border: 1px solid #1a2744; border-radius: 14px;
    padding: 1.2rem 1.4rem; text-align: center;
    transition: transform .2s, box-shadow .2s;
}
.kpi-card:hover { transform: translateY(-3px); box-shadow: 0 8px 30px rgba(79,172,254,.18); }
.kpi-value {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 2.1rem; font-weight: 700; margin: 0;
}
.kpi-label { font-size: 0.78rem; color: #6b7a99; text-transform: uppercase; letter-spacing: 1.5px; margin-top: 4px; }
.kpi-blue .kpi-value  { color: #4facfe; }
.kpi-red .kpi-value   { color: #ff4d6d; }
.kpi-green .kpi-value { color: #00d68f; }
.kpi-amber .kpi-value { color: #ffa94d; }

/* ── Risk result ── */
.result-card {
    border-radius: 16px; padding: 2rem; text-align: center;
    animation: fadeIn .4s ease-in;
}
.result-malicious {
    background: rgba(255,77,109,.08);
    border: 1.5px solid #ff4d6d;
    box-shadow: 0 0 30px rgba(255,77,109,.15);
}
.result-suspect {
    background: rgba(255,140,66,.08);
    border: 1.5px solid #ff8c42;
    box-shadow: 0 0 30px rgba(255,140,66,.15);
}
.result-normal {
    background: rgba(0,214,143,.08);
    border: 1.5px solid #00d68f;
    box-shadow: 0 0 30px rgba(0,214,143,.15);
}
.result-label {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 2rem; font-weight: 700; letter-spacing: 2px;
}
.result-malicious .result-label { color: #ff4d6d; }
.result-suspect   .result-label { color: #ff8c42; }
.result-normal    .result-label { color: #00d68f; }
.result-prob { font-size: 1.1rem; color: #8892a4; margin-top: .5rem; }

/* ── Section divider ── */
.divider { height: 1px; background: linear-gradient(90deg, transparent, #1a2744, transparent); margin: 1.5rem 0; }

/* ── Filter tag badge ── */
.badge-m { background:#ff4d6d22; color:#ff4d6d; border:1px solid #ff4d6d; border-radius:20px; padding:2px 12px; font-size:.75rem; }
.badge-n { background:#00d68f22; color:#00d68f; border:1px solid #00d68f; border-radius:20px; padding:2px 12px; font-size:.75rem; }

/* ── Derived feature box ── */
.derived-box {
    background: #0a1120; border: 1px solid #1a2744; border-radius: 10px;
    padding: .9rem 1.1rem; font-size: .85rem; color: #8892a4;
}
.derived-val { color: #4facfe; font-weight: 600; font-size: 1rem; }

/* ── Table tweaks ── */
[data-testid="stDataFrame"] { border: 1px solid #1a2744; border-radius: 10px; }

/* ── Sidebar nav radio ── */
[data-testid="stSidebar"] .stRadio label { font-size: .92rem; }

/* ── Form section headers ── */
.form-header {
    font-size: 1.05rem; font-weight: 600; color: #cdd6f4;
    border-bottom: 1px solid #1a2744; padding-bottom: .4rem; margin: .8rem 0 .5rem;
}
.form-header i { color: #4facfe; margin-right: .45rem; }
.form-subheader {
    font-size: .82rem; font-weight: 600; color: #6b7a99;
    text-transform: uppercase; letter-spacing: 1.2px; margin: .8rem 0 .25rem;
}
.form-subheader i { color: #4facfe; margin-right: .35rem; }

/* ── Result icon ── */
.result-icon { font-size: 2.4rem; margin-bottom: .5rem; }
.result-malicious .result-icon { color: #ff4d6d; }
.result-suspect   .result-icon { color: #ff8c42; }
.result-normal    .result-icon { color: #00d68f; }

@keyframes fadeIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# DATA & MODEL LOADERS
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data
def load_data():
    df = pd.read_csv("data/user_features.csv")
    return df

@st.cache_resource
def load_model():
    pipeline = joblib.load("models/pipeline.pkl")
    with open("models/freq_maps.json", encoding="utf-8") as f:
        freq_maps = json.load(f)
    with open("models/metrics.json", encoding="utf-8") as f:
        metrics = json.load(f)
    with open("models/perf_data.json", encoding="utf-8") as f:
        perf = json.load(f)
    with open("models/feature_cols.json", encoding="utf-8") as f:
        feature_cols = json.load(f)
    return pipeline, freq_maps, metrics, perf, feature_cols

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="brand-title"><i class="fas fa-shield-halved" style="-webkit-text-fill-color:#4facfe;margin-right:.4rem;"></i>CyberRisk</div>', unsafe_allow_html=True)
    st.markdown('<div class="brand-sub">Insider Threat Detection</div>', unsafe_allow_html=True)
    st.markdown("<hr style='border-color:#1a2744;margin:1rem 0'>", unsafe_allow_html=True)

    page =  option_menu(
    menu_title="Menu principal",
    options=["Analyse", "Simulation","Filtration", "Performance"],
    icons=["bar-chart", "arrow-repeat", "filter", "speedometer"],
    menu_icon="cast",
    default_index=0
)
   

    st.markdown("<hr style='border-color:#1a2744;margin:1rem 0'>", unsafe_allow_html=True)
    st.markdown(
        "<div style='font-size:.7rem;color:#3a4459;text-align:center;'>"
        "Logistic Regression · C=0.1<br>118 614 utilisateurs · AUC 0.874</div>",
        unsafe_allow_html=True,
    )

# ─────────────────────────────────────────────────────────────────────────────
# LOAD
# ─────────────────────────────────────────────────────────────────────────────
df = load_data()
pipeline, freq_maps, metrics, perf, feature_cols = load_model()

DEPTS   = sorted(df["employee_department"].unique())
CAMPUS  = sorted(df["employee_campus"].unique())
POSTS   = sorted(df["employee_position"].unique())
PAYS    = sorted(df["employee_origin_country"].unique())

# ─────────────────────────────────────────────────────────────────────────────
# ─── PAGE : ANALYSE ──────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
if page == "Analyse":
    st.markdown('<div class="section-title">Analyse du Dataset</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Vue d\'ensemble statistique · 118 614 employés</div>', unsafe_allow_html=True)

    n_total     = len(df)
    n_mal       = df["is_malicious"].sum()
    n_norm      = n_total - n_mal
    pct_mal     = n_mal / n_total * 100

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="kpi-card kpi-blue"><p class="kpi-value">{n_total:,}</p><p class="kpi-label">Total utilisateurs</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="kpi-card kpi-red"><p class="kpi-value">{n_mal:,}</p><p class="kpi-label">Malveillants</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="kpi-card kpi-green"><p class="kpi-value">{n_norm:,}</p><p class="kpi-label">Normaux</p></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="kpi-card kpi-amber"><p class="kpi-value">{pct_mal:.1f}%</p><p class="kpi-label">Taux de menace</p></div>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    col_l, col_r = st.columns([1, 1.4])

    with col_l:
        # Pie chart
        fig_pie = go.Figure(go.Pie(
            labels=["Normal", "Malveillant"],
            values=[n_norm, n_mal],
            hole=.62,
            marker=dict(colors=["#00d68f", "#ff4d6d"],
                        line=dict(color="#070b14", width=2)),
            textinfo="percent+label",
            textfont=dict(size=13, color="#cdd6f4"),
        ))
        fig_pie.update_layout(
            title=dict(text="Distribution des classes", font=dict(color="#cdd6f4", size=15)),
            paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
            legend=dict(font=dict(color="#cdd6f4"), bgcolor="rgba(0,0,0,0)"),
            margin=dict(t=50, b=10, l=10, r=10),
            annotations=[dict(text=f"<b>{pct_mal:.1f}%</b><br>menace",
                              font=dict(size=18, color="#ff4d6d"),
                              showarrow=False)]
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_r:
        # Malicious rate by department
        dept_stats = (
            df.groupby("employee_department")["is_malicious"]
              .agg(["sum", "count"])
              .assign(rate=lambda x: x["sum"] / x["count"] * 100)
              .sort_values("rate", ascending=True)
              .reset_index()
        )
        fig_dept = go.Figure(go.Bar(
            y=dept_stats["employee_department"],
            x=dept_stats["rate"],
            orientation="h",
            marker=dict(
                color=dept_stats["rate"],
                colorscale=[[0,"#00d68f"],[0.5,"#ffa94d"],[1,"#ff4d6d"]],
                showscale=False,
            ),
            text=dept_stats["rate"].apply(lambda v: f"{v:.1f}%"),
            textposition="outside",
            textfont=dict(color="#cdd6f4", size=11),
        ))
        fig_dept.update_layout(
            title=dict(text="Taux de menace par département (%)", font=dict(color="#cdd6f4", size=15)),
            paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
            xaxis=dict(color="#4a5568", showgrid=True, gridcolor="#1a2744"),
            yaxis=dict(color="#cdd6f4", tickfont=dict(size=11)),
            margin=dict(t=50, b=10, l=10, r=60), height=400,
        )
        st.plotly_chart(fig_dept, use_container_width=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Feature distributions
    st.markdown("#### Distribution des features clés", unsafe_allow_html=False)
    feat_sel = st.selectbox(
        "Choisir une feature",
        ["data_exfiltration_score", "activity_score", "total_printed_pages",
         "num_printed_pages_off_hours", "num_entries", "burned_from_other",
         "off_hours_print_ratio", "hostility_country_level"],
        label_visibility="collapsed",
    )

    df_mal  = df[df["is_malicious"] == 1][feat_sel]
    df_norm = df[df["is_malicious"] == 0][feat_sel]

    fig_hist = go.Figure()
    fig_hist.add_trace(go.Histogram(
        x=df_norm, name="Normal", nbinsx=40,
        marker_color="#00d68f", opacity=.65,
    ))
    fig_hist.add_trace(go.Histogram(
        x=df_mal, name="Malveillant", nbinsx=40,
        marker_color="#ff4d6d", opacity=.75,
    ))
    fig_hist.update_layout(
        barmode="overlay",
        title=dict(text=f"Distribution — {feat_sel}", font=dict(color="#cdd6f4", size=14)),
        paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
        xaxis=dict(color="#4a5568", gridcolor="#1a2744"),
        yaxis=dict(color="#4a5568", gridcolor="#1a2744"),
        legend=dict(font=dict(color="#cdd6f4")),
        margin=dict(t=45, b=20), height=300,
    )
    st.plotly_chart(fig_hist, use_container_width=True)

   


# ─────────────────────────────────────────────────────────────────────────────
# ─── PAGE : SIMULATION ───────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
elif page == "Simulation":
    st.markdown('<div class="section-title">Simulation — Classification</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Entrez le profil d\'un utilisateur pour évaluer son niveau de risque</div>', unsafe_allow_html=True)

    with st.form("simulation_form"):
        c_l, c_r = st.columns(2)

        with c_l:
            st.markdown('<p class="form-header"><i class="fas fa-user-tie"></i> Profil employ&eacute;</p>', unsafe_allow_html=True)
            dept    = st.selectbox("Département",          DEPTS)
            campus  = st.selectbox("Campus",               CAMPUS)
            post    = st.selectbox("Poste",                POSTS)
            pays    = st.selectbox("Pays d'origine",       PAYS)
            senior  = st.slider("Ancienneté (années)",     0, 31, 3)
            classif = st.selectbox("Classification sécurité", [1, 2, 3, 4],
                                   format_func=lambda x: f"Niveau {x}")
            criminal = st.checkbox("Antécédents judiciaires")

        with c_r:
            st.markdown('<p class="form-header"><i class="fas fa-clipboard-list"></i> Comportement observ&eacute;</p>', unsafe_allow_html=True)
            st.markdown('<p class="form-subheader"><i class="fas fa-door-open"></i> Acc&egrave;s physique</p>', unsafe_allow_html=True)
            num_entries   = st.slider("Entrées sur site",                 0, 4, 1)
            weekend_entry = st.checkbox("Accès le weekend")
            num_uni_camp  = st.slider("Nombre de campus fréquentés",      1, 3, 1)

            st.markdown('<p class="form-subheader"><i class="fas fa-print"></i> Impression</p>', unsafe_allow_html=True)
            total_print   = st.slider("Pages imprimées (total)",          0, 109, 5)
            off_print     = st.slider("Pages imprimées hors-heures",      0, 12, 0)

            st.markdown('<p class="form-subheader"><i class="fas fa-hard-drive"></i> Fichiers</p>', unsafe_allow_html=True)
            files_burned  = st.slider("Fichiers détruits",                0, 95, 0)
            burned_other  = st.checkbox("Fichiers détruits depuis source externe")

            st.markdown('<p class="form-subheader"><i class="fas fa-plane-departure"></i> Voyage</p>', unsafe_allow_html=True)
            hostility     = st.select_slider(
                "Niveau menace du pays visité",
                options=[0, 1, 2, 3],
                value=0,
                format_func=lambda x: ["Aucun", "Faible", "Moyen", "Élevé"][x],
            )

        submitted = st.form_submit_button(
            "Analyser le risque",
            use_container_width=True,
            type="primary",
        )

    if submitted:
        # ── Compute derived features ──────────────────────────────────────
        off_hours_ratio  = off_print / (total_print + 1)
        activity_sc      = num_entries * 2 + num_uni_camp * 3 + int(weekend_entry) * 5
        data_exfil_sc    = files_burned * 3 + int(burned_other) * 5 + total_print * 1 + off_print * 4

        # ── Build input row (exact column order) ──────────────────────────
        row = {
            "employee_department":        dept,
            "employee_campus":            campus,
            "employee_position":          post,
            "employee_seniority_years":   senior,
            "employee_classification":    classif,
            "has_criminal_record":        int(criminal),
            "employee_origin_country":    pays,
            "total_printed_pages":        total_print,
            "num_printed_pages_off_hours": off_print,
            "burned_from_other":          int(burned_other),
            "hostility_country_level":    hostility,
            "num_entries":                num_entries,
            "entry_during_weekend":       int(weekend_entry),
            "off_hours_print_ratio":      off_hours_ratio,
            "activity_score":             activity_sc,
            "data_exfiltration_score":    data_exfil_sc,
        }
        X_sim = pd.DataFrame([row])

        # ── Frequency encoding ────────────────────────────────────────────
        for col in ["employee_position", "employee_origin_country"]:
            fm     = freq_maps[col]
            min_v  = min(fm.values())
            X_sim[col] = X_sim[col].map(fm).fillna(min_v)

        # ── Predict ───────────────────────────────────────────────────────
        pred  = pipeline.predict(X_sim)[0]
        proba = pipeline.predict_proba(X_sim)[0]
        prob_mal  = proba[1]

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

        if prob_mal >= 0.55:
            risk_level = "malicious"
        elif prob_mal >= 0.30:
            risk_level = "suspect"
        else:
            risk_level = "normal"

        risk_meta = {
            "malicious": {
                "border": "#ff4d6d", "bg": "rgba(255,77,109,.06)", "glow": "rgba(255,77,109,.18)",
                "icon": "fa-triangle-exclamation", "label": "MALVEILLANT",
                "msg": "Comportements hautement suspects.<br>Investigation imm&eacute;diate recommand&eacute;e.",
            },
            "suspect": {
                "border": "#ff8c42", "bg": "rgba(255,140,66,.06)", "glow": "rgba(255,140,66,.18)",
                "icon": "fa-circle-exclamation", "label": "SUSPECT",
                "msg": "Activit&eacute; anormale d&eacute;tect&eacute;e.<br>Surveillance renforc&eacute;e conseill&eacute;e.",
            },
            "normal": {
                "border": "#00d68f", "bg": "rgba(0,214,143,.06)", "glow": "rgba(0,214,143,.18)",
                "icon": "fa-circle-check", "label": "FAIBLE",
                "msg": "Aucune anomalie d&eacute;tect&eacute;e.<br>Profil consid&eacute;r&eacute; comme normal.",
            },
        }
        rm = risk_meta[risk_level]

        st.markdown(f"""
        <style>
        [data-testid="stVerticalBlockBorderWrapper"] {{
            border-color: {rm['border']} !important;
            border-radius: 16px !important;
            background: {rm['bg']} !important;
            box-shadow: 0 0 32px {rm['glow']} !important;
        }}
        </style>
        """, unsafe_allow_html=True)

        with st.container(border=True):
            inner_l, inner_r = st.columns([1, 1.1])

            with inner_l:
                st.markdown(f"""
                <div style="text-align:center;padding:1.4rem .5rem;animation:fadeIn .4s ease-in;">
                    <div style="font-size:3rem;color:{rm['border']};margin-bottom:.5rem;">
                        <i class="fas {rm['icon']}"></i>
                    </div>
                    <div style="font-family:'Space Grotesk',sans-serif;font-size:2rem;
                                font-weight:700;color:{rm['border']};letter-spacing:2px;">
                        {rm['label']}
                    </div>
                    <div style="font-size:1rem;color:#8892a4;margin:.7rem 0;">
                        Score de risque :
                        <b style="color:{rm['border']};font-size:1.5rem;">&nbsp;{prob_mal:.1%}</b>
                    </div>
                    <div style="display:inline-block;margin-top:.4rem;padding:.3rem 1rem;
                                border:1px solid {rm['border']}55;border-radius:20px;
                                font-size:.8rem;color:#6b7a99;line-height:1.6;">
                        {rm['msg']}
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with inner_r:
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=prob_mal * 100,
                    number=dict(suffix="%", font=dict(size=30, color="#cdd6f4")),
                    gauge=dict(
                        axis=dict(range=[0, 100], tickfont=dict(color="#4a5568")),
                        bar=dict(color=rm['border'], thickness=.3),
                        bgcolor="rgba(0,0,0,0)",
                        borderwidth=0,
                        steps=[
                            dict(range=[0,  30], color="#0d2a1d"),
                            dict(range=[30, 55], color="#2a1a08"),
                            dict(range=[55, 100], color="#2a0d14"),
                        ],
                        threshold=dict(line=dict(color="#cdd6f4", width=2), value=prob_mal * 100),
                    ),
                    title=dict(text="Score de risque", font=dict(color="#6b7a99", size=13)),
                ))
                fig_gauge.update_layout(
                    paper_bgcolor="rgba(0,0,0,0)",
                    margin=dict(t=30, b=10, l=20, r=20),
                    height=245,
                )
                st.plotly_chart(fig_gauge, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# ─── PAGE : FILTRATION ───────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
elif page == "Filtration":
    st.markdown('<div class="section-title">Filtration du Dataset</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Explorez, filtrez et téléchargez les données</div>', unsafe_allow_html=True)

    with st.expander("Filtres", expanded=True):
        f1, f2, f3 = st.columns(3)
        with f1:
            sel_dept = st.multiselect(
                "Département",
                options=DEPTS,
                default=[],
                placeholder="Tous les départements",
            )
            sel_campus = st.multiselect(
                "Campus",
                options=CAMPUS,
                default=[],
                placeholder="Tous les campus",
            )
        with f2:
            sel_risk = st.selectbox(
                "Statut de risque",
                options=["Tous", "Normal uniquement", "Malveillants uniquement"],
            )
            sel_classif = st.multiselect(
                "Classification sécurité",
                options=[1, 2, 3, 4],
                default=[],
                format_func=lambda x: f"Niveau {x}",
                placeholder="Toutes les classifications",
            )
        with f3:
            sel_hostility = st.multiselect(
                "Niveau hostilité pays",
                options=[0, 1, 2, 3],
                default=[],
                format_func=lambda x: ["0 - Aucun","1 - Faible","2 - Moyen","3 - Élevé"][x],
                placeholder="Tous les niveaux",
            )
            seniority_range = st.slider("Ancienneté (années)", 0, 31, (0, 31))

    # Apply filters
    filtered = df.copy()
    if sel_dept:     filtered = filtered[filtered["employee_department"].isin(sel_dept)]
    if sel_campus:   filtered = filtered[filtered["employee_campus"].isin(sel_campus)]
    if sel_classif:  filtered = filtered[filtered["employee_classification"].isin(sel_classif)]
    if sel_hostility:filtered = filtered[filtered["hostility_country_level"].isin(sel_hostility)]
    if sel_risk == "Normal uniquement":     filtered = filtered[filtered["is_malicious"] == 0]
    elif sel_risk == "Malveillants uniquement": filtered = filtered[filtered["is_malicious"] == 1]
    filtered = filtered[filtered["employee_seniority_years"].between(*seniority_range)]

    n_filt  = len(filtered)
    n_f_mal = filtered["is_malicious"].sum()
    n_f_nor = n_filt - n_f_mal

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="kpi-card kpi-blue"><p class="kpi-value">{n_filt:,}</p><p class="kpi-label">Résultats</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="kpi-card kpi-red"><p class="kpi-value">{n_f_mal:,}</p><p class="kpi-label">Malveillants</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(f'<div class="kpi-card kpi-green"><p class="kpi-value">{n_f_nor:,}</p><p class="kpi-label">Normaux</p></div>', unsafe_allow_html=True)
    with c4:
        pct = n_f_mal / n_filt * 100 if n_filt > 0 else 0.0
        st.markdown(f'<div class="kpi-card kpi-amber"><p class="kpi-value">{pct:.1f}%</p><p class="kpi-label">Taux de menace</p></div>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Visual breakdown of filtered
    if n_filt > 0:
        col_v1, col_v2 = st.columns(2)
        with col_v1:
            dept_filt = (
                filtered.groupby("employee_department")["is_malicious"]
                .agg(["sum","count"])
                .assign(rate=lambda x: x["sum"]/x["count"]*100)
                .sort_values("rate", ascending=False)
                .reset_index()
            )
            fig_df = px.bar(
                dept_filt, x="employee_department", y="rate",
                color="rate",
                color_continuous_scale=[[0,"#00d68f"],[.5,"#ffa94d"],[1,"#ff4d6d"]],
                labels={"rate":"Taux (%)", "employee_department":""},
                title="Taux menace / département (filtré)",
            )
            fig_df.update_layout(
                paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
                font=dict(color="#cdd6f4"), xaxis_tickangle=-30,
                coloraxis_showscale=False, margin=dict(t=45,b=20), height=300,
            )
            st.plotly_chart(fig_df, use_container_width=True)

        with col_v2:
            campus_filt = filtered.groupby(["employee_campus","is_malicious"]).size().reset_index(name="count")
            campus_filt["label"] = campus_filt["is_malicious"].map({0:"Normal",1:"Malveillant"})
            fig_cf = px.bar(
                campus_filt, x="employee_campus", y="count",
                color="label",
                color_discrete_map={"Normal":"#00d68f","Malveillant":"#ff4d6d"},
                barmode="group",
                labels={"count":"Nombre","employee_campus":"","label":""},
                title="Distribution par campus (filtré)",
            )
            fig_cf.update_layout(
                paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
                font=dict(color="#cdd6f4"),
                legend=dict(bgcolor="rgba(0,0,0,0)"),
                margin=dict(t=45,b=20), height=300,
            )
            st.plotly_chart(fig_cf, use_container_width=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Table
    cols_display = ["employee_department","employee_campus","employee_position",
                    "employee_origin_country","employee_seniority_years",
                    "employee_classification","has_criminal_record",
                    "total_printed_pages","num_printed_pages_off_hours",
                    "burned_from_other","hostility_country_level",
                    "num_entries","entry_during_weekend","is_malicious"]

    display_df = filtered[cols_display].copy()
    display_df["is_malicious"] = display_df["is_malicious"].map({0:"Normal", 1:"MALVEILLANT"})

    st.dataframe(
        display_df.head(500),
        use_container_width=True,
        height=380,
    )
    if n_filt > 500:
        st.caption(f"Affichage des 500 premières lignes sur {n_filt:,}")

    # Download
    csv_data = filtered.to_csv(index=False).encode("utf-8")
    st.download_button(
        label=f"Telecharger le dataset filtre ({n_filt:,} lignes)",
        data=csv_data,
        file_name="dataset_filtre.csv",
        mime="text/csv",
        use_container_width=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ─── PAGE : PERFORMANCE ──────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
elif page == "Performance":
    st.markdown('<div class="section-title">Performance du Modèle</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Logistic Regression · C=0.1 · class_weight=balanced · max_iter=1000</div>', unsafe_allow_html=True)

    best = metrics[0]  # C=0.1 is first

    m1, m2, m3, m4, m5 = st.columns(5)
    def metric_card(col, val, label, color_cls):
        col.markdown(
            f'<div class="kpi-card {color_cls}"><p class="kpi-value">{val}</p>'
            f'<p class="kpi-label">{label}</p></div>',
            unsafe_allow_html=True,
        )

    metric_card(m1, f"{best['Accuracy']:.3f}",  "Accuracy",  "kpi-blue")
    metric_card(m2, f"{best['Precision']:.3f}",  "Precision", "kpi-amber")
    metric_card(m3, f"{best['Recall']:.3f}",     "Recall",    "kpi-green")
    metric_card(m4, f"{best['F1']:.3f}",          "F1 Score",  "kpi-blue")
    metric_card(m5, f"{best['AUC-ROC']:.3f}",    "AUC-ROC",   "kpi-red")

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    col_cm, col_roc = st.columns(2)

    with col_cm:
        cm = perf["confusion_matrix"]
        z  = [[cm[1][1], cm[1][0]], [cm[0][1], cm[0][0]]]
        x_labels = ["Prédit: Malveillant", "Prédit: Normal"]
        y_labels = ["Réel: Malveillant",   "Réel: Normal"]
        annotations = []
        for i, row_v in enumerate(z):
            for j, val in enumerate(row_v):
                annotations.append(dict(
                    x=x_labels[j], y=y_labels[i],
                    text=f"<b>{val:,}</b>",
                    showarrow=False,
                    font=dict(size=18, color="#cdd6f4"),
                ))

        fig_cm = go.Figure(go.Heatmap(
            z=z, x=x_labels, y=y_labels,
            colorscale=[[0,"#023C94"],[0.3,"#17519e"],[1,"#5eb1ff"]],
            showscale=False,
            text=[[str(v) for v in row_v] for row_v in z],
        ))
        fig_cm.update_layout(
            title=dict(text="Matrice de Confusion", font=dict(color="#cdd6f4", size=15)),
            paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
            font=dict(color="#cdd6f4"),
            margin=dict(t=50, b=20, l=20, r=20), height=340,
            annotations=annotations,
        )
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_roc:
        fpr = perf["fpr"]
        tpr = perf["tpr"]
        auc = perf["auc_roc"]

        fig_roc = go.Figure()
        fig_roc.add_trace(go.Scatter(
            x=fpr, y=tpr, mode="lines",
            name=f"ROC (AUC = {auc:.3f})",
            line=dict(color="#4facfe", width=2.5),
            fill="tozeroy",
            fillcolor="rgba(79,172,254,.08)",
        ))
        fig_roc.add_trace(go.Scatter(
            x=[0, 1], y=[0, 1], mode="lines",
            name="Aléatoire (AUC=0.5)",
            line=dict(color="#4a5568", width=1.5, dash="dash"),
        ))
        fig_roc.add_annotation(
            x=0.65, y=0.35,
            text=f"<b>AUC = {auc:.3f}</b>",
            showarrow=False,
            font=dict(size=16, color="#4facfe"),
            bgcolor="#0d1b2a",
        )
        fig_roc.update_layout(
            title=dict(text="Courbe ROC", font=dict(color="#cdd6f4", size=15)),
            paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
            xaxis=dict(title="Taux Faux Positifs", color="#4a5568", gridcolor="#1a2744"),
            yaxis=dict(title="Taux Vrais Positifs", color="#4a5568", gridcolor="#1a2744"),
            legend=dict(font=dict(color="#cdd6f4"), bgcolor="rgba(0,0,0,0)"),
            margin=dict(t=50, b=30, l=50, r=20), height=340,
        )
        st.plotly_chart(fig_roc, use_container_width=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Feature importance
    names  = perf["feature_names"]
    coefs  = perf["feature_coefs"]
    fi_df  = pd.DataFrame({"feature": names, "importance": coefs})
    fi_df  = fi_df.sort_values("importance", ascending=True).tail(15)

    fig_fi = go.Figure(go.Bar(
        y=fi_df["feature"],
        x=fi_df["importance"],
        orientation="h",
        marker=dict(
            color=fi_df["importance"],
            colorscale=[[0,"#1e3a5f"],[0.5,"#4facfe"],[1,"#00f2fe"]],
            showscale=False,
        ),
        text=fi_df["importance"].apply(lambda v: f"{v:.3f}"),
        textposition="outside",
        textfont=dict(color="#cdd6f4", size=10),
    ))
    fig_fi.update_layout(
        title=dict(text="Top 15 Features — |Coefficient| LR", font=dict(color="#cdd6f4", size=15)),
        paper_bgcolor="#0d1b2a", plot_bgcolor="#0d1b2a",
        xaxis=dict(color="#4a5568", gridcolor="#1a2744"),
        yaxis=dict(color="#cdd6f4", tickfont=dict(size=10)),
        margin=dict(t=50, b=10, l=20, r=60), height=450,
    )
    st.plotly_chart(fig_fi, use_container_width=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Model comparison table
    st.markdown("#### Comparaison des variantes LR")
    metrics_df = pd.DataFrame(metrics)
    metrics_df.columns = ["Modèle","Accuracy","Precision","Recall","F1","AUC-ROC"]

    def highlight_best(col):
        if col.name == "Modèle":
            return [""] * len(col)
        best_val = col.max()
        return ["background-color:#0d2a1d;color:#00d68f;font-weight:600" if v == best_val
                else "" for v in col]

    st.dataframe(
        metrics_df.style.apply(highlight_best),
        use_container_width=True,
        hide_index=True,
    )
