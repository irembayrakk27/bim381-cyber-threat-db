import streamlit as st
import psycopg2
import pandas as pd


# --------------------------------------------------
# Page configuration
# --------------------------------------------------

st.set_page_config(
    page_title="Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# Custom navy theme
# --------------------------------------------------

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #071426 0%, #0b1d35 55%, #102744 100%);
        color: #e6edf7;
    }

    [data-testid="stSidebar"] {
        background: #08172a;
        border-right: 1px solid #203b5b;
    }

    [data-testid="stHeader"] {
        background: rgba(7, 20, 38, 0.85);
    }

    h1, h2, h3 {
        color: #eaf2ff !important;
    }

    p, label, span {
        color: #d2deee;
    }

    [data-testid="stMetric"] {
        background: #102744;
        border: 1px solid #294766;
        padding: 18px;
        border-radius: 12px;
    }

    [data-testid="stMetricLabel"] {
        color: #a9c4e3 !important;
    }

    [data-testid="stMetricValue"] {
        color: #65b8ff !important;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #294766;
        border-radius: 10px;
    }

    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {
        background-color: #102744;
        border-color: #365777;
    }

    div[data-testid="stSlider"] {
        padding-top: 10px;
    }

    .stButton button {
        background-color: #164b78;
        color: white;
        border: 1px solid #3479ad;
        border-radius: 8px;
    }

    hr {
        border-color: #294766;
    }
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# Database connection
# --------------------------------------------------

def get_connection():
    return psycopg2.connect(
        dbname="cyber_threat_db",
        user="ybayrirem",
        host="/var/run/postgresql"
    )


def fetch_data(query, params=None):
    connection = get_connection()

    try:
        return pd.read_sql_query(
            query,
            connection,
            params=params
        )
    finally:
        connection.close()


# --------------------------------------------------
# Sidebar navigation
# --------------------------------------------------

st.sidebar.title("🛡️ Cyber Threat System")
st.sidebar.caption("Vulnerability Management Platform")

page = st.sidebar.radio(
    "Navigation",
    ["General Overview", "Vulnerabilities"]
)

st.sidebar.divider()
st.sidebar.caption("PostgreSQL 16.15")
st.sidebar.caption("Database: cyber_threat_db")


# --------------------------------------------------
# Main application
# --------------------------------------------------

st.title("Cyber Threat Intelligence & Vulnerability Management")
st.caption("Siber Tehdit İstihbaratı ve Zafiyet Yönetim Sistemi")

try:

    # ==============================================
    # GENERAL OVERVIEW
    # ==============================================

    if page == "General Overview":

        st.header("General Overview")

        total_cves = fetch_data(
            "SELECT COUNT(*) AS total FROM cve"
        ).iloc[0]["total"]

        critical_cves = fetch_data(
            "SELECT COUNT(*) AS total FROM cve WHERE cvss_score >= 9.0"
        ).iloc[0]["total"]

        total_products = fetch_data(
            "SELECT COUNT(*) AS total FROM product"
        ).iloc[0]["total"]

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Vulnerabilities", total_cves)
        col2.metric("Critical Vulnerabilities", critical_cves)
        col3.metric("Products", total_products)

        # Severity distribution

        st.subheader("Vulnerabilities by Severity")

        severity_data = fetch_data("""
            SELECT
                CASE
                    WHEN cvss_score >= 9.0 THEN 'Critical'
                    WHEN cvss_score >= 7.0 THEN 'High'
                    WHEN cvss_score >= 4.0 THEN 'Medium'
                    ELSE 'Low'
                END AS severity,
                COUNT(*) AS total
            FROM cve
            GROUP BY severity;
        """)

        severity_order = [
            "Critical",
            "High",
            "Medium",
            "Low"
        ]

        severity_data = (
            severity_data
            .set_index("severity")
            .reindex(severity_order, fill_value=0)
        )

        st.bar_chart(
            severity_data,
            y="total",
            horizontal=True
        )

        # Product summary

        st.subheader("Products in the Database")

        products = fetch_data("""
            SELECT
                p.name AS product,
                pv.version_number AS version,
                COUNT(DISTINCT cpv.cve_id) AS vulnerability_count
            FROM product p
            JOIN product_version pv
                ON pv.product_id = p.product_id
            LEFT JOIN cve_product_version cpv
                ON cpv.product_id = pv.product_id
                AND cpv.version_number = pv.version_number
            GROUP BY p.name, pv.version_number
            ORDER BY p.name;
        """)

        st.dataframe(
            products,
            use_container_width=True,
            hide_index=True
        )


    # ==============================================
    # VULNERABILITIES
    # ==============================================

    elif page == "Vulnerabilities":

        st.header("Vulnerability Records")

        cves = fetch_data("""
            SELECT
                cve_id,
                description,
                published_date,
                cvss_score
            FROM cve
            ORDER BY cvss_score DESC, published_date DESC;
        """)

        if cves.empty:
            st.info("No vulnerability records found.")

        else:

            # CVSS filter

            min_score = float(cves["cvss_score"].min())
            max_score = float(cves["cvss_score"].max())

            score_range = st.slider(
                "CVSS Score Range",
                min_value=0.0,
                max_value=10.0,
                value=(min_score, max_score),
                step=0.1
            )

            # Search

            search = st.text_input(
                "Search by CVE ID or description"
            )

            filtered = cves[
                cves["cvss_score"].between(
                    score_range[0],
                    score_range[1]
                )
            ]

            if search:
                filtered = filtered[
                    filtered["cve_id"].str.contains(
                        search,
                        case=False,
                        na=False,
                        regex=False
                    )
                    |
                    filtered["description"].str.contains(
                        search,
                        case=False,
                        na=False,
                        regex=False
                    )
                ]

            st.write(f"Records found: {len(filtered)}")

            # Shortened descriptions in the list

            display_cves = filtered.copy()

            display_cves["description"] = (
                display_cves["description"]
                .fillna("")
                .apply(
                    lambda value:
                    value[:160] + "..."
                    if len(value) > 160
                    else value
                )
            )

            st.dataframe(
                display_cves,
                use_container_width=True,
                hide_index=True
            )

            # CVE details

            st.subheader("Vulnerability Details")

            selected_cve = st.selectbox(
                "Select a CVE",
                cves["cve_id"].tolist()
            )

            details = fetch_data("""
                SELECT
                    cve_id,
                    description,
                    published_date,
                    cvss_score
                FROM cve
                WHERE cve_id = %s;
            """, (selected_cve,))

            selected_details = details.iloc[0]

            detail_col1, detail_col2 = st.columns(2)

            detail_col1.metric(
                "CVSS Score",
                str(selected_details["cvss_score"])
            )

            detail_col2.metric(
                "Published Date",
                str(selected_details["published_date"])
            )

            st.markdown("**Description**")
            st.write(selected_details["description"])

            # Associated CWE records

            st.markdown("**Associated CWE Records**")

            cwe_data = fetch_data("""
                SELECT
                    w.cwe_id,
                    w.name
                FROM cwe w
                JOIN cve_cwe cw
                    ON cw.cwe_id = w.cwe_id
                WHERE cw.cve_id = %s
                ORDER BY w.cwe_id;
            """, (selected_cve,))

            if cwe_data.empty:
                st.info("No associated CWE records.")

            else:
                st.dataframe(
                    cwe_data,
                    use_container_width=True,
                    hide_index=True
                )

            # Affected products and versions

            st.markdown("**Affected Products and Versions**")

            product_data = fetch_data("""
                SELECT
                    p.name AS product,
                    pv.version_number AS version
                FROM cve_product_version cpv
                JOIN product p
                    ON p.product_id = cpv.product_id
                JOIN product_version pv
                    ON pv.product_id = cpv.product_id
                    AND pv.version_number = cpv.version_number
                WHERE cpv.cve_id = %s
                ORDER BY p.name;
            """, (selected_cve,))

            if product_data.empty:
                st.info("No affected product information.")

            else:
                st.dataframe(
                    product_data,
                    use_container_width=True,
                    hide_index=True
                )

            # Reference links

            st.markdown("**Reference Links**")

            reference_data = fetch_data("""
                SELECT reference_url
                FROM cve_reference
                WHERE cve_id = %s
                ORDER BY reference_url;
            """, (selected_cve,))

            if reference_data.empty:
                st.info("No reference links available.")

            else:
                st.dataframe(
                    reference_data,
                    column_config={
                        "reference_url": st.column_config.LinkColumn(
                            "Reference URL",
                            display_text="Open reference"
                        )
                    },
                    use_container_width=True,
                    hide_index=True
                )


except Exception as error:

    st.error(f"Application error: {error}")

    st.info(
        "Please check the PostgreSQL connection "
        "and database schema."
    )
