import React, { useEffect, useState } from "react";
import "bootstrap/dist/css/bootstrap.min.css";
import styles from "../uploadAnnouncement.module.css";
function SelectType(props) {
  const { setTitleValue, b_title } = props;

  // useEffect(() => {
  //     console.log(titleValue.)
  // }, [titleValue]);
  const changeTitleValue = (titleEvent) => {
    const newTitle = titleEvent.target.value;
    //titleInputRef.current = TitleValue; // 삭제
    setTitleValue(newTitle); // 추가
  };

  return (
    <div>
      <div className="create-window">
        <div className="form-floating mb-3">
          <input
            type="text"
            className="form-control"
            id="flootingInput"
            name="b_title"
            value={b_title}
            onChange={changeTitleValue}
          />
          <label htmlFor="flootingInput">제목</label>
        </div>
      </div>
    </div>
  );
}

export default SelectType;
