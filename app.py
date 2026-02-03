import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import importlib
import es_service
importlib.reload(es_service)
from es_service import fetch_cve_data, fetch_summary_stats

# --- Page Config ---
st.set_page_config(
    page_title="CVE Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Premium Look ---
st.markdown("""
<style>
    /* Global Styling */
    .stApp {
        background-color: #0E1117;
    }
    h1, h2, h3 {
        color: #FFFFFF;
        font-family: 'Inter', sans-serif;
    }
    
    /* Metrics Styling */
    div[data-testid="stMetric"] {
        background-color: #262730;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #363945;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    div[data-testid="stMetricLabel"] {
        color: #A3A8B8;
    }
    div[data-testid="stMetricValue"] {
        color: #00D4FF;
    }
    
    /* Table Styling */
    div[data-testid="stDataFrame"] {
        background-color: #262730;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #363945;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

# --- Session State Initialization ---
if 'selected_year' not in st.session_state:
    st.session_state.selected_year = "All"
if 'severity_filter' not in st.session_state:
    st.session_state.severity_filter = [] # Default empty means All
if 'filter_mode' not in st.session_state:
    st.session_state.filter_mode = "All Time"
if 'selected_date' not in st.session_state:
    st.session_state.selected_date = pd.to_datetime("today").date()
if 'cve_status_type' not in st.session_state:
    st.session_state.cve_status_type = "Published (New)"
if 'score_range' not in st.session_state:
    st.session_state.score_range = (0.0, 10.0)
if 'kev_filter' not in st.session_state:
    st.session_state.kev_filter = False
if 'epss_range' not in st.session_state:
    st.session_state.epss_range = (0.0, 1.0)
if 'product_filter' not in st.session_state:
    st.session_state.product_filter = ""
if 'vendor_filter' not in st.session_state:
    st.session_state.vendor_filter = ""
if 'cvss_version_filter' not in st.session_state:
    st.session_state.cvss_version_filter = []

# --- Sidebar ---
with st.sidebar:
    st.title("🛡️ CVE Explorer")
    st.markdown("---")
    
    st.subheader("Filter Configurations")
    
    # Mode Selection (Simplified)
    # Mode Selection (Simplified)
    filter_mode = st.radio(
        "Observation Mode",
        ["All Time", "Specific Date", "Date Range"],
        index=0 if st.session_state.filter_mode == "All Time" else (1 if st.session_state.filter_mode == "Specific Date" else 2),
        key="filter_mode"
    )
    
    selected_date = None
    date_field = "published" # Default
    
    if st.session_state.filter_mode != "All Time":
        if st.session_state.filter_mode == "Specific Date":
             selected_date = st.date_input("Select Date", st.session_state.selected_date, key="selected_date")
        else: # Date Range
             d_col1, d_col2 = st.columns(2)
             with d_col1:
                 start_d = st.date_input("Start Date", pd.to_datetime("today").date() - pd.Timedelta(days=7), key="start_date_range")
             with d_col2:
                 end_d = st.date_input("End Date", pd.to_datetime("today").date(), key="end_date_range")
             selected_date = (start_d, end_d)

        cve_status_type = st.radio(
            "CVE Status Type",
            ["Published (New)", "Modified (Updated)"],
            index=0 if st.session_state.cve_status_type == "Published (New)" else 1,
            key="cve_status_type"
        )
        date_field = "published" if "New" in cve_status_type else "lastModified"
        
    st.markdown("---")
    
    # 1. Severity Filter (Multi-select)
    st.markdown("**Severity Level**")
    sev_options = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    if not isinstance(st.session_state.severity_filter, list):
         st.session_state.severity_filter = []
         
    severity_filter_list = st.multiselect(
        "Select Severity",
        options=sev_options,
        default=st.session_state.severity_filter,
        key="severity_filter_widget", 
        help="Leave empty to select ALL"
    )
    st.session_state.severity_filter = severity_filter_list

    # 4. Affected Software/Hardware
    st.markdown("---")
    st.markdown("**Affected Components**")
    
    vendor_input = st.text_input(
        "Vendor Name",
        value=st.session_state.vendor_filter,
        key="vendor_filter",
        placeholder="e.g. Microsoft, Apache"
    )

    product_input = st.text_input(
        "Product Name",
        value=st.session_state.product_filter,
        key="product_filter",
        placeholder="e.g. Exchange Server"
    )

    # 2. Risk Scoring (Gauge/Slider)
    st.markdown("---")
    st.markdown("**Risk Scoring**")
    
    cvss_version = st.multiselect(
        "CVSS Version",
        ["3.1", "3.0", "2.0"],
        default=st.session_state.cvss_version_filter,
        key="cvss_version_filter",
        help="Filter by CVSS version availability"
    )
    
    score_val = st.slider(
        "CVSS Base Score",
        0.0, 10.0,
        st.session_state.score_range,
        step=0.1,
        key="score_range"
    )
    
    # 3. Intelligence Filters
    st.markdown("---")
    st.markdown("**Threat Intelligence**")
    
    kev_val = st.checkbox(
        "Has CISA KEV",
        value=st.session_state.kev_filter,
        key="kev_filter",
        help="Known Exploited Vulnerabilities"
    )
    
    epss_val = st.slider(
        "EPSS Probability",
        0.0, 1.0,
        st.session_state.epss_range,
        step=0.01,
        key="epss_range",
        help="Exploit Prediction Scoring System"
    )
    
    st.markdown("---")
    
    # Year Selector
    year_options = ["All"] + [str(y) for y in range(1999, 2026)]
    if st.session_state.selected_year not in year_options:
         st.session_state.selected_year = "All"
         
    selected_year = st.selectbox(
        "Index Year",
        year_options,
        index=year_options.index(st.session_state.selected_year),
        key="selected_year"
    )
    
    search_term = st.text_input("Search", placeholder="CVE-ID or Description...", key="main_search")
    
    def reset_filters_callback():
        st.session_state.severity_filter = []
        if 'severity_filter_widget' in st.session_state:
            st.session_state.severity_filter_widget = []
        st.session_state.score_range = (0.0, 10.0)
        st.session_state.kev_filter = False
        st.session_state.epss_range = (0.0, 1.0)
        st.session_state.vendor_filter = ""
        st.session_state.product_filter = ""
        st.session_state.cvss_version_filter = []
        st.session_state.selected_year = "All"
        st.session_state.main_search = ""

    st.button("Reset Filters", type="primary", on_click=reset_filters_callback)

# --- Helper functions for interactions ---
def set_daily_filter(mode_type):
    st.session_state.filter_mode = "Specific Date"
    st.session_state.selected_date = pd.to_datetime("today").date()
    if mode_type == "new":
        st.session_state.cve_status_type = "Published (New)"
    else:
        st.session_state.cve_status_type = "Modified (Updated)"

# --- Data Loading ---
@st.cache_data(ttl=600)
def load_data(year, search, sev, date_val, d_field, score, kev, epss, vendor, product, cvss_ver):
    index = f"list-cve-{year}" if year != "All" else "list-cve-*"
    
    sev_arg = sev if sev else "All"
    
    try:
        df, total_hits = fetch_cve_data(
            index_pattern=index, 
            search_text=search if search else None, 
            severity_filter=sev_arg,
            date_filter=date_val,
            date_field=d_field,
            score_range=score,
            kev_filter=kev,
            epss_range=epss,
            vendor_filter=vendor if vendor else None,
            product_filter=product if product else None,
            cvss_version_filter=cvss_ver if cvss_ver else None
        )
        return df, total_hits, None
    except Exception as e:
        return None, 0, str(e)

@st.cache_data(ttl=600)
def load_stats(year, d_field, search, sev, date_val, score, kev, epss, vendor, product, cvss_ver):
    index = f"list-cve-{year}" if year != "All" else "list-cve-*"
    sev_arg = sev if sev else "All"
    try:
        # Now passing all filters to stats too!
        stats = fetch_summary_stats(
            index_pattern=index, 
            date_field=d_field,
            search_text=search if search else None,
            severity_filter=sev_arg,
            date_filter=date_val,
            score_range=score,
            kev_filter=kev,
            epss_range=epss,
            vendor_filter=vendor if vendor else None,
            product_filter=product if product else None,
            cvss_version_filter=cvss_ver if cvss_ver else None
        )
        return stats, None
    except Exception as e:
        return None, str(e)

# --- Secondary Data Load (Today's highlights) ---
@st.cache_data(ttl=300)
def load_today_metrics():
    today_str = pd.Timestamp.now().strftime('%Y-%m-%d')
    try:
        _, new_count = fetch_cve_data(date_filter=today_str, date_field="published", size=1)
        _, mod_count = fetch_cve_data(date_filter=today_str, date_field="lastModified", size=1)
        return new_count, mod_count
    except:
        return 0, 0

# --- Main Content ---

st.title("🛡️ Vulnerability Intelligence Center")
st.markdown("Real-time dashboard for Common Vulnerabilities and Exposures (CVE).")

# Load Main Data
df_cves, total_cves, error_msg = load_data(
    selected_year, 
    search_term, 
    st.session_state.severity_filter, 
    selected_date if st.session_state.filter_mode == "Specific Date" else None, 
    date_field,
    st.session_state.score_range,
    st.session_state.kev_filter,
    st.session_state.epss_range,
    st.session_state.vendor_filter,
    st.session_state.product_filter,
    st.session_state.cvss_version_filter
)

# Load Stats with same filters
stats_aggs, stats_error = load_stats(
    selected_year, 
    date_field,
    search_term,
    st.session_state.severity_filter,
    selected_date if st.session_state.filter_mode == "Specific Date" else None,
    st.session_state.score_range,
    st.session_state.kev_filter,
    st.session_state.epss_range,
    st.session_state.vendor_filter,
    st.session_state.product_filter,
    st.session_state.cvss_version_filter
)
new_today, mod_today = load_today_metrics()

if error_msg:
    st.error(f"Failed to connect to Elasticsearch: {error_msg}")
    st.stop()



# --- New Top Bar ---
c_top1, c_top2 = st.columns([3, 1])
with c_top1:
    st.markdown("### 📅 Today's Intelligence")
with c_top2:
    if filter_mode == "All Time":
        current_mode = "All Time"
    elif filter_mode == "Specific Date":
        current_mode = f"{selected_date}"
    else:
        # Date Range
        try:
             current_mode = f"{selected_date[0]} to {selected_date[1]}"
        except:
             current_mode = "Date Range"

    st.markdown(
        f"""
        <div style="text-align: right; background-color: #262730; padding: 5px 10px; border-radius: 5px; border: 1px solid #464B5C;">
            <small style="color: #A3A8B8;">Context:</small> <strong>{current_mode}</strong>
        </div>
        """, 
        unsafe_allow_html=True
    )


# --- Metrics Grid ---
if stats_aggs:
    # Extract counts from aggregations
    sev_buckets = {b['key']: b['doc_count'] for b in stats_aggs['severity_counts']['buckets']}
    cnt_crit = sev_buckets.get('CRITICAL', 0)
    cnt_high = sev_buckets.get('HIGH', 0)
    cnt_med = sev_buckets.get('MEDIUM', 0)
    cnt_low = sev_buckets.get('LOW', 0)
    
    cnt_kev = stats_aggs.get('kev_count', {}).get('doc_count', 0)
    cnt_vendors = stats_aggs.get('unique_vendors', {}).get('value', 0)
    cnt_products = stats_aggs.get('unique_products', {}).get('value', 0)
else:
    cnt_crit = cnt_high = cnt_med = cnt_low = cnt_kev = cnt_vendors = cnt_products = 0

# Row 1: Severities & Total
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("CRITICAL", f"{cnt_crit:,}", help="Vulnerabilities with CRITICAL severity")
with m2:
    st.metric("HIGH", f"{cnt_high:,}", help="Vulnerabilities with HIGH severity")
with m3:
    st.metric("MEDIUM", f"{cnt_med:,}", help="Vulnerabilities with MEDIUM severity")
with m4:
    st.metric("LOW", f"{cnt_low:,}", help="Vulnerabilities with LOW severity")

# Row 2: Intelligence & Scope
m5, m6, m7, m8 = st.columns(4)
with m5:
    st.metric("KEV Exploited", f"{cnt_kev:,}", help="Known Exploited Vulnerabilities (CISA)")
with m6:
    st.metric("Affected Vendors", f"{cnt_vendors:,}", help="Unique Vendors impacted")
with m7:
    st.metric("Affected Products", f"{cnt_products:,}", help="Unique Products impacted")
with m8:
    # Today's updates metrics in one card or split? User asked for New/Updated checks.
    # We display the main Total here as a summary.
    st.metric("Total Filtered", f"{total_cves:,}")

st.markdown("---")

# --- Charts Section ---
st.markdown("### 📈 Visual Analytics")

if stats_aggs:
    tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Rankings", "Vendor Trends", "Product Trends"])
    
    # Tab 1: Original Overview
    with tab1:
        c1, c2 = st.columns([1, 2])
        
        with c1:
            st.subheader("Severity Distribution")
            buckets = stats_aggs['severity_counts']['buckets']
            if buckets:
                sev_data = pd.DataFrame(buckets)
                fig_pie = px.pie(
                    sev_data, 
                    values='doc_count', 
                    names='key',
                    color='key',
                    color_discrete_map={
                        "HIGH": "#FF4B4B", 
                        "CRITICAL": "#8B0000", 
                        "MEDIUM": "#FFA500", 
                        "LOW": "#00FF00"
                    },
                    hole=0.4
                )
                fig_pie.update_layout(
                    template="plotly_dark", 
                    showlegend=True,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='#262730',
                    margin=dict(t=30, b=10, l=10, r=10),
                    legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
                )
                
                # Interactive Selection
                event = st.plotly_chart(
                    fig_pie, 
                    use_container_width=True, 
                    theme=None,
                    on_select="rerun",
                    selection_mode="points"
                )
                
                # Application of filter from chart click
                if event and event["selection"]["points"]:
                    clicked_point = event["selection"]["points"][0]
                    try:
                        point_idx = clicked_point["point_index"]
                        selected_sev = sev_data.iloc[point_idx]['key']
                        
                        # Toggle logic for multiselect
                        current_filters = st.session_state.severity_filter
                        if not isinstance(current_filters, list):
                            current_filters = []
                            
                        if selected_sev in current_filters:
                            current_filters.remove(selected_sev)
                        else:
                            current_filters.append(selected_sev)
                            
                        st.session_state.severity_filter = current_filters
                        st.rerun()
                    except:
                        pass
            else:
                st.info("No severity data available.")

        with c2:
            st.subheader("General Activity Trend")
            overview_buckets = stats_aggs['activity_over_time']['buckets']
            if overview_buckets:
                trend_data = pd.DataFrame(overview_buckets)
                if not trend_data.empty:
                    trend_data['key_as_string'] = pd.to_datetime(trend_data['key_as_string']).dt.year
                    fig_bar = px.bar(
                        trend_data, 
                        x='key_as_string', 
                        y='doc_count',
                        labels={'key_as_string': 'Year', 'doc_count': 'Count'},
                        color='doc_count',
                        color_continuous_scale='Viridis'
                    )
                    fig_bar.update_layout(
                        template="plotly_dark", 
                        xaxis_type='category',
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='#262730',
                        margin=dict(t=10, b=10, l=10, r=10)
                    )
                    st.plotly_chart(fig_bar, use_container_width=True, theme=None)
            else:
                st.info("No timeline data available.")

        # Histogram of Scores
        st.subheader("CVSS Score Distribution")
        score_buckets = stats_aggs['score_histogram']['buckets']
        if score_buckets:
            score_data = pd.DataFrame(score_buckets)
            if not score_data.empty:
                fig_hist = px.bar(
                    score_data,
                    x='key',
                    y='doc_count',
                    labels={'key': 'Score', 'doc_count': 'Count'},
                    color='key',
                    color_continuous_scale='RdYlGn_r' # Red for high scores
                )
                fig_hist.update_layout(
                    template="plotly_dark",
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='#262730',
                    margin=dict(t=10, b=10, l=10, r=10)
                )
                st.plotly_chart(fig_hist, use_container_width=True, theme=None)
    
    # Tab 2: Rankings (With Interactive Filtering)
    with tab2:
        c_r1, c_r2 = st.columns(2)
        
        # --- Top Vendors Chart ---
        with c_r1:
            st.subheader("Top 5 Vendors")
            if 'top_vendors' in stats_aggs:
                v_buckets = stats_aggs['top_vendors']['buckets']
                if v_buckets:
                    df_v = pd.DataFrame(v_buckets)
                    fig_v = px.bar(
                        df_v, x='doc_count', y='key', orientation='h',
                        labels={'doc_count': 'Count', 'key': 'Vendor'},
                        text='doc_count'
                    )
                    fig_v.update_traces(marker_color='#00D4FF', textposition='outside')
                    fig_v.update_layout(
                        template="plotly_dark",
                        yaxis={'categoryorder':'total ascending'},
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='#262730',
                        margin=dict(t=10, b=10, l=10, r=10)
                    )
                    
                    # Interactive Vendor Click
                    event_v = st.plotly_chart(fig_v, use_container_width=True, theme=None, on_select="rerun", selection_mode="points")
                    if event_v and event_v["selection"]["points"]:
                        try:
                            v_idx = event_v["selection"]["points"][0]["point_index"]
                            selected_vendor = df_v.iloc[v_idx]['key']
                            # Toggle logic: if same vendor selected, clear it
                            if st.session_state.vendor_filter == selected_vendor:
                                st.session_state.vendor_filter = ""
                            else:
                                st.session_state.vendor_filter = selected_vendor
                            st.rerun()
                        except:
                            pass
                else:
                    st.info("No vendor data.")
        
        # --- Top Products Chart ---
        with c_r2:
            st.subheader("Top 5 Products")
            if 'top_products' in stats_aggs:
                p_buckets = stats_aggs['top_products']['buckets']
                if p_buckets:
                    df_p = pd.DataFrame(p_buckets)
                    fig_p = px.bar(
                        df_p, x='doc_count', y='key', orientation='h',
                        labels={'doc_count': 'Count', 'key': 'Product'},
                        text='doc_count'
                    )
                    fig_p.update_traces(marker_color='#FF00FF', textposition='outside')
                    fig_p.update_layout(
                        template="plotly_dark",
                        yaxis={'categoryorder':'total ascending'},
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='#262730',
                        margin=dict(t=10, b=10, l=10, r=10)
                    )
                    
                    # Interactive Product Click
                    event_p = st.plotly_chart(fig_p, use_container_width=True, theme=None, on_select="rerun", selection_mode="points")
                    if event_p and event_p["selection"]["points"]:
                         try:
                            p_idx = event_p["selection"]["points"][0]["point_index"]
                            selected_product = df_p.iloc[p_idx]['key']
                            if st.session_state.product_filter == selected_product:
                                st.session_state.product_filter = ""
                            else:
                                st.session_state.product_filter = selected_product
                            st.rerun()
                         except:
                            pass
                else:
                    st.info("No product data.")
        
        c_r3, c_r4 = st.columns(2)
        
        # --- Status Breakdown Chart ---
        with c_r3:
            st.subheader("Status Breakdown")
            if 'vuln_status_counts' in stats_aggs:
                s_buckets = stats_aggs['vuln_status_counts']['buckets']
                if s_buckets:
                    df_s = pd.DataFrame(s_buckets)
                    fig_s = px.pie(
                        df_s, values='doc_count', names='key',
                        color_discrete_sequence=px.colors.sequential.RdBu,
                        hole=0.4
                    )
                    fig_s.update_layout(
                        template="plotly_dark",
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='#262730',
                        margin=dict(t=10, b=10, l=10, r=10),
                         legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
                    )
                    st.plotly_chart(fig_s, use_container_width=True, theme=None)
                else:
                    st.info("No status data.")
        
        # --- Weaknesses Chart ---
        with c_r4:
            st.subheader("Top 5 Weaknesses (CWE)")
            if 'top_weaknesses' in stats_aggs:
                w_buckets = stats_aggs['top_weaknesses']['buckets']
                if w_buckets:
                    df_w = pd.DataFrame(w_buckets)
                    fig_w = px.bar(
                        df_w, x='doc_count', y='key', orientation='h',
                        labels={'doc_count': 'Count', 'key': 'CWE'},
                        text='doc_count'
                    )
                    fig_w.update_traces(marker_color='#FFA500', textposition='outside')
                    fig_w.update_layout(
                        template="plotly_dark",
                        yaxis={'categoryorder':'total ascending'},
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='#262730',
                        margin=dict(t=10, b=10, l=10, r=10)
                    )
                    
                    # Interactive Weakness Search (Sets text search)
                    event_w = st.plotly_chart(fig_w, use_container_width=True, theme=None, on_select="rerun", selection_mode="points")
                    if event_w and event_w["selection"]["points"]:
                        try:
                            w_idx = event_w["selection"]["points"][0]["point_index"]
                            selected_weakness = df_w.iloc[w_idx]['key']
                            # Appends to main search
                            if st.session_state.main_search == selected_weakness:
                                st.session_state.main_search = ""
                            else:
                                st.session_state.main_search = selected_weakness
                            st.rerun()
                        except:
                            pass
                else:
                    st.info("No weakness data.")

    # Function to parse nested timeline buckets
    def parse_nested_timeline(agg_data):
        rows = []
        for bucket in agg_data['buckets']:
            name = bucket['key']
            for time_bucket in bucket['history']['buckets']:
                rows.append({
                    "Name": name,
                    "Year": pd.to_datetime(time_bucket['key_as_string']).year,
                    "Count": time_bucket['doc_count']
                })
        return pd.DataFrame(rows)

    # Tab 3: Vendor Trends (Line Chart)
    with tab3:
        st.subheader("Top 5 Vendors Over Time")
        if 'top_vendors' in stats_aggs:
            df_vendor = parse_nested_timeline(stats_aggs['top_vendors'])
            if not df_vendor.empty:
                fig_vendor = px.line(
                    df_vendor, 
                    x="Year", 
                    y="Count", 
                    color="Name",
                    markers=True,
                    title="Vulnerability Trends by Vendor"
                )
                fig_vendor.update_layout(
                    template="plotly_dark",
                    xaxis_type='category',
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='#262730',
                    margin=dict(t=40, b=10, l=10, r=10),
                    hovermode="x unified"
                )
                st.plotly_chart(fig_vendor, use_container_width=True, theme=None)
            else:
                st.info("No vendor data found.")
        else:
             st.info("Stats not loaded (agg missing).")

    # Tab 4: Product Trends (Line Chart)
    with tab4:
        st.subheader("Top 5 Products Over Time")
        if 'top_products' in stats_aggs:
            df_prod = parse_nested_timeline(stats_aggs['top_products'])
            if not df_prod.empty:
                fig_prod = px.line(
                    df_prod, 
                    x="Year", 
                    y="Count", 
                    color="Name", 
                    markers=True,
                    title="Vulnerability Trends by Product"
                )
                fig_prod.update_layout(
                    template="plotly_dark",
                    xaxis_type='category',
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='#262730',
                    margin=dict(t=40, b=10, l=10, r=10),
                    hovermode="x unified"
                )
                st.plotly_chart(fig_prod, use_container_width=True, theme=None)
            else:
                st.info("No product data found.")
        else:
             st.info("Stats not loaded (agg missing).")


# --- Detail List ---
st.subheader("Detailed CVE List")

if not df_cves.empty:
    # Select columns to display
    cols_to_show = ['id', 'sev', 'score', 'published', 'vendors', 'products', 'desc']
    # Check which columns actually exist
    available_cols = [c for c in cols_to_show if c in df_cves.columns]
    
    # Custom coloring for table (Severity)
    def color_sev(val):
        color = '#FFFFFF'
        if val == 'HIGH': color = '#FF4B4B'
        elif val == 'MEDIUM': color = '#FFA500'
        elif val == 'LOW': color = '#90EE90'
        return f'color: {color}'

    st.dataframe(
        df_cves[available_cols].style.map(color_sev, subset=['sev']),
        use_container_width=True,
        height=400
    )
    
    # Drill Down
    st.caption("Expand below to see raw details of the first 5 records")
    with st.expander("Raw Data Inspection"):
        st.json(df_cves.head().to_dict(orient='records'))
else:
    st.info("No CVEs found matching your criteria.")

