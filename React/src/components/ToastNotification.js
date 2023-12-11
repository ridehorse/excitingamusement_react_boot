// ToastNotification.js
import React from "react";
import { BsHeartFill } from "react-icons/bs";
// import "../css/ToastNotification.css";

const ToastNotification = ({ toast }) => {
  const { show, message, type } = toast; // type 속성 추가

  const showClassName = show ? "show" : "";
  const bgColorClassName = type === "success" ? "bg-primary" : ""; // 바탕색 지정
  const textColorClassName =
    type === "success" ? "text-white" : "text-gray-dark"; // 텍스트 색상 지정
  const textIconClassName =
    type === "success" ? "bi bi-balloon-heart-fill" : "bi bi-balloon-heart"; // 아이콘 지정
  return (
    <div
      className={`toast start-50 translate-middle-x ${
        toast.show ? "show" : ""
      }`}
      style={{
        position: "fixed",
        bottom: 20,
        zIndex: 1000,
      }}
    >
      <div className={`${bgColorClassName} ${textColorClassName}`}>
        <div className="toast-body">
          <p className={`${textIconClassName}`} style={{ fontSize: "1.3rem" }}>
            <BsHeartFill
              className="custom-icon"
              style={{ fontSize: "1.8rem" }}
            />
            {toast.message}
          </p>
        </div>
      </div>
    </div>
  );
};

export default ToastNotification;
