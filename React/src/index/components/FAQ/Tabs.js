import React, { useState } from "react";
import "../../css/FAQ/FAQ.css";

const Tabs = ({changeF_type, f_type}) => {


  const liStyle = {
    borderWidth: '1px 1px 0 1px',
    borderStyle: 'solid',
    background: '#ededed',
    borderColor: '#999999',
    fontWeight: 'bold',
    borderRadius: '5px 5px 0 0'
  };

  return (
    <div style={{ clear: "both" }}>
      <div style={{ margin: "30px 0" }}>
        <h1>자주 묻는 질문</h1>
      </div>
      <div className="tab_wrap">
        <div className="tab">
          <ul className="tabs">
            <li
              className={`tab-link${f_type === null ? " current" : ""}`}
              id="li-0"
              style={f_type === null ? liStyle : {}}
              onClick={() => changeF_type(null)}
            >
              <div style={{ width: "100%", height: "100%"}}>전체</div>
            </li>
            <li
              className={`tab-link${f_type === 1 ? " current" : ""}`}
              id="li-1"
              style={f_type === 1 ? liStyle : {}}
              onClick={() => changeF_type(1)}
            >
              <div style={{ width: "100%", height: "100%"}}>이용정보</div>
            </li>
            <li
              className={`tab-link${f_type === 2 ? " current" : ""}`}
              id="li-2"
              style={f_type === 2 ? liStyle : {}}
              onClick={() => changeF_type(2)}
            >
              <div style={{ width: "100%", height: "100%"}}>우대정보/이벤트</div>
            </li>
            <li
              className={`tab-link${f_type === 3 ? " current" : ""}`}
              id="li-3"
              style={f_type === 3 ? liStyle : {}}
              onClick={() => changeF_type(3)}
            >
              <div style={{ width: "100%", height: "100%"}}>예매</div>
            </li>
            <li
              className={`tab-link${f_type === 4 ? " current" : ""}`}
              id="li-4"
              style={f_type === 4 ? liStyle : {}}
              onClick={() => changeF_type(4)}
            >
              <div style={{ width: "100%", height: "100%"}}>기타</div>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Tabs;
