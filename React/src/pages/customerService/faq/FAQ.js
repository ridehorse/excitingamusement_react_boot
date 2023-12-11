import React, { useEffect, useRef, useState } from "react";
import "./FAQ.css";
import axios from "axios";
import Advertisement from "./component/Advertisement";
import Tabs from "./component/Tabs";
import FaqItem from "./component/FaqItem";
import { useLocation } from "react-router-dom";
import PagingNumberLogic from "./component/PagingNumberLogic";

const FAQ = () => {
  const [faqs, setFaqs] = useState([]);
  const [f_type, setF_type] = useState(null);
  // 페이지 상태 변수 추가
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const [pageNumber, setPageNumber] = useState(1);
  const location = useLocation();
  const [loading, setLoading] = useState(true);

  // 페이지가 로드될 때 faq 목록을 불러와 상태에 저장합니다.
  // 탭(type)이동 시 현재 페이지 초기화 (2페이지인 상태에서 옆에 탭 누를 시 1페이지로 초기화)

  useEffect(() => {
    currentPageInit();
    fetchFaqs();
  }, [f_type]);

  useEffect(() => {
    fetchFaqs();
  }, [currentPage]);

  const changeF_type = (typeNum) => {
    console.log("너 변하니");
    setF_type(typeNum);
  };

  const currentPageInit = () => {
    setCurrentPage(1);
  };

  const fetchFaqs = async () => {
    const addressParams = new URLSearchParams(location.search);
    const addressPageNum = addressParams.get("pageNum");
    const addressFtype = addressParams.get("ftype");
    // console.log("@@@@@@@@@@@@@@@@@@@@@@@@@@@qqqq" + addressFtype)
    // const adressF_type = f_typeNullCheck(addressFtype);
    // console.log("@@@@@@@@@@@@@@@@@@@@@@@@@@@qqqq" + f_type)
    // const pageNum = pageNumNullCheck(addressPageNum);

    const response = await axios.get(
      "http://localhost:8080/customer/getfaqList",
      {
        params: {
          f_type: f_type,
          pageNum: currentPage,
        },
      }
    );
    setFaqs(response.data.content);
    setTotalPages(response.data.totalPages);
    setLoading(false);
    // setTotalPages(responseTotalCount.data.totalPages);
  };

  const toggleFaq = (index) => {
    setFaqs(
      faqs.map((faq, i) =>
        i === index
          ? { ...faq, active: !faq.active }
          : { ...faq, active: false }
      )
    );
  };

  return (
    <>
      {loading ? (
        <div>Loading...</div>
      ) : (
        <div>
          <Advertisement />
          <section className="notice">
            <div className="faqWrap">
              <Tabs changeF_type={changeF_type} faqs={faqs} />
              <div
                className="faq-container"
                style={{ minHeight: 500, textAlign: "left", clear: "both" }}
              >
                {faqs.map((faq, index) => (
                  <FaqItem
                    key={faq.faq_num}
                    faq={faq}
                    index={index}
                    toggleFaq={toggleFaq}
                  />
                ))}
              </div>
              <div style={{ textAlign: "center" }}>
                <span className="faq_page_nation">
                  <PagingNumberLogic
                    pageNumber={pageNumber}
                    totalPages={totalPages}
                    f_type={f_type}
                    setCurrentPage={setCurrentPage}
                  ></PagingNumberLogic>
                </span>
              </div>
            </div>
          </section>
        </div>
      )}
    </>
  );
};

export default FAQ;
