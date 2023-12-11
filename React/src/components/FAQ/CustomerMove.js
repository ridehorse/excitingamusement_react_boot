import React, { useState } from "react";
import "../../css/FAQ/CustomerMove.css"; // 경로에 맞게 변경하세요.
// import '../../css/FAQ.css';

const CustomerMove = () => {
  const [listVisible, setListVisible] = useState(false);

  const toggleListVisibility = () => {
    setListVisible(!listVisible);
  };

  return (
    <div className="menu_select">
      <span
        onClick={() => {
          window.location.href = "/";
        }}
        style={{ cursor: "pointer" }}
      >
        <img src="https://cdn-icons-png.flaticon.com/512/20/20176.png" />|
      </span>
      <div className="text" onClick={toggleListVisibility}>
        <span>
          <b>공지사항</b>
        </span>

        <img src="https://cdn-icons-png.flaticon.com/512/3519/3519316.png" />
        {listVisible && (
          <ul className={`option-list`}>
            <li>
              <a href="/customer/announcement">공지사항</a>
            </li>
            <li>
              <a href="/customer/faq?f_type=">FAQ</a>
            </li>
            <li>
              <a href="/customer/announcementInquiry">문의하기</a>
            </li>
            <li>
              <a href="/customer/consultationDetails">상담내역</a>
            </li>
          </ul>
        )}
      </div>
    </div>
  );
};

export default CustomerMove;
