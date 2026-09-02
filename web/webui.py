import streamlit as st

if __name__ == "__main__":

    st.markdown(
        """
        <style>
        [data-testid="stSidebarUserContent"] {
            padding-top: 20px;
        }
        .block-container {
            padding-top: 25px;
        }
        [data-testid="stBottomBlockContainer"] {
            padding-bottom: 20px;
        }
        """,
        unsafe_allow_html=True,
    )

    st.title("Red-MIRROR")
    st.info("The legacy Milvus knowledge-base interface has been removed. Retrieval is handled by the Red-MIRROR RAG pipeline.")
