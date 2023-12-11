import React, { useEffect, useState } from "react";
import Advertisement from "../components/FAQ/Advertisement";
import "../css/FAQ/FAQ.css"; 
import CustomerMove from "../components/FAQ/CustomerMove";
import Tabs from "../components/FAQ/Tabs";
import FaqItem from "../components/FAQ/FaqItem";
import Pagination from '../components/FAQ/Pagination';
import axios from "axios";

const FAQ = () => {
  const [faqs, setFaqs] = useState([]);
  const [f_type, setF_type] = useState(null);
  const [start, setStart] = useState(null);
  // 페이지 상태 변수 추가
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(0);
  const pageSize = 5;

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
    setF_type(typeNum);
  };

  const currentPageInit = () => {
    setCurrentPage(1);
  };

  const fetchFaqs = async () => {
// responseTotalCount 요청은 오로지 토탈페이지를 얻기 위한 요청
    const responseTotalCount = await axios.get('http://localhost:8080/customer/faq', {
      params : {
        f_type,
        start: null
      }
    });

    const response = await axios.get('http://localhost:8080/customer/getfaqList', {
      params : {
        f_type,
        start: (currentPage - 1) * pageSize
      }
    });
    
    setFaqs(response.data);
    setTotalPages(responseTotalCount.data.totalPages);
    console.log(responseTotalCount.data.totalPages);
  };

  const toggleFaq = (index) => {
    setFaqs(
      faqs.map((faq, i) =>
        i === index ? { ...faq, active: !faq.active } : { ...faq, active: false }
      )
    );
  };

  return (
    <>
       <Advertisement />
       <div className="wrap">
         <div className="customerMove">
           <CustomerMove />  
         </div>
         <Tabs changeF_type={changeF_type} f_type={f_type}/>
         <div className="faq-container">
         {faqs.map((faq, index) => (
           <FaqItem key={faq.faq_num} faq={faq} index={index} toggleFaq={toggleFaq} />
             ))}
          <Pagination totalPages={totalPages} currentPage={currentPage} setCurrentPage={setCurrentPage} />
         </div>
       </div>
    </>
  );
};

export default FAQ;
