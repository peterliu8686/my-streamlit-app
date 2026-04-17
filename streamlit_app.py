import streamlit as st

st.title("我的第一個 Python 網頁")
st.write("如果你看到這個畫面，表示佈署成功了！")

# 簡單的互動
number = st.slider("選個數字", 0, 100)
st.write(f"你選的數字是：{number}")
