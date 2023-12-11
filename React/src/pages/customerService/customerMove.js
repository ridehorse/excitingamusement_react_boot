import React, { useState } from "react";
import "./customerMove.css";

function CustomerMove({ children }) {
  const [menuOpen, setMenuOpen] = useState(0);

  const move = () => {
    let list = document.querySelector(".customermove .option-list");
    setMenuOpen(1);
    //이거 상태관리로 값에 따라 보이고 안보이게 하셈
    if (list.style.overflow === "hidden" || list.style.overflow === "") {
      list.style.overflow = "visible";
    } else {
      list.style.overflow = "hidden";
    }
  };

  const handleLinkClick = (link) => {
    window.location.href = link;
  };

  return (
    <div className="menu_select customermove" onClick={move}>
      <span onClick={() => handleLinkClick("/")} style={{ cursor: "pointer" }}>
        <img
          src="https://cdn-icons-png.flaticon.com/512/20/20176.png"
          alt="1"
        />
        |
      </span>
      <div className="text" style={{ marginRight: 200, marginTop: 100 }}>
        <span>
          <b>공지사항</b>
        </span>
        <img
          src="https://cdn-icons-png.flaticon.com/512/3519/3519316.png"
          alt="1"
        />
        <ul className="option-list" onClick={move}>
          <li>
            <a href="#" onClick={() => handleLinkClick("/announcement")}>
              공지사항
            </a>
          </li>
          <li>
            <a href="#" onClick={() => handleLinkClick("/faq")}>
              FAQ
            </a>
          </li>
          <li>
            <a href="#" onClick={() => handleLinkClick("/insertInquiry")}>
              문의하기
            </a>
          </li>
          <li>
            <a href="#" onClick={() => handleLinkClick("/inquiry")}>
              상담내역
            </a>
          </li>
        </ul>
      </div>
    </div>
  );
}

export default CustomerMove;
