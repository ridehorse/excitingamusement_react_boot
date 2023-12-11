import React, { useState } from "react";

const Tabs = ({ changeF_type, f_type, faqs }) => {
  const [currentTab, setCurrentTab] = useState(0);

  const liStyle = {
    borderWidth: "1px 1px 1px 1px",
    borderStyle: "solid",
    background: "#ededed",
    borderColor: "#999999",
    fontWeight: "bold",
    borderRadius: "5px 5px 0 0",
  };

  const tabsData = [
    { id: "li-0", className: "tab-link current", type: "전체" },
    { id: "li-1", className: `tab-link`, type: "이용정보" },
    { id: "li-2", className: `tab-link`, type: "우대/이벤트" },
    { id: "li-3", className: `tab-link`, type: "예매" },
    { id: "li-4", className: `tab-link`, type: "기타" },
  ];

  const TabClick = (index) => {
    setCurrentTab(index);
  };

  return (
    <div style={{ clear: "both" }}>
      <div style={{ margin: "30px 0" }}>
        <h1>자주 묻는 질문</h1>
      </div>
      <div className="fatTab_wrap">
        <div className="faqTab" style={{ marginLeft: 450 }}>
          <ul
            className="faqTabs"
            style={{ textAlign: "center", arginLeft: 50, marginBottom: 50 }}
          >
            {faqs &&
              tabsData.map((e, index) => (
                <li
                  className={`tab-link${
                    index === currentTab ? " current" : ""
                  }`}
                  id={e.id}
                  style={index === currentTab ? liStyle : {}}
                  onClick={() => {
                    changeF_type(e.type);
                    TabClick(index);
                  }}
                  key={index}
                >
                  <div style={{ width: "100%", height: "100%", right: 20 }}>
                    {e.type}
                  </div>
                </li>
              ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Tabs;
