import React, { useState } from "react";
import axios from "axios";
import styles from "../inquiryDetail.module.css";
function InquiryAnswer({ inquiryNum, viewData }) {
  const [adminAnswer, setAdminAnswer] = useState("");

  const submitAnswer = () => {
    const b_content = adminAnswer;
    const b_title = viewData[0].b_title;
    const ref = viewData[0].ref;
    if (window.confirm("답변하시겠습니까?")) {
      if (window.confirm("답변은 취소가 안됩니다 확정하시겠습니까?")) {
        axios
          .post("http://localhost:8080/customer/inquiryAnswer", {
            inquiry_num: inquiryNum,
            b_content: b_content,
            b_title: b_title,
            member_id: "hong1",
            ref: ref,
          })
          .then((response) => {
            window.alert("답변 완료");
            window.location.reload();
          });
      }
    }
  };

  const changeAnswer = (event) => {
    setAdminAnswer(event.target.value);
  };

  return (
    <div>
      <p>관리자 답변</p>
      <textarea
        rows="10"
        name="b_content"
        className={styles.adminAnswerContent}
        id="adminAnswerContent"
        style={{ width: "100%" }}
        onChange={changeAnswer}
      ></textarea>
      <input type="button" value="관리자 답변" onClick={submitAnswer} />
    </div>
  );
}

export default InquiryAnswer;
