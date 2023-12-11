import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Board from "../board";
import $ from "jquery";

function Tabs() {
  const [data, setData] = useState(0);
  const [pageCount, setPageCount] = useState(10);
  const history = useNavigate();

  useEffect(() => {}, []);

  //tab
  const tabEvent = [
    { name: "전체", id: "li-0", link: "0" },
    { name: "국내", id: "li-1", link: "1" },
    { name: "해외", id: "li-2", link: "2" },
    { name: "질문", id: "li-3", link: "3" },
    { name: "자유", id: "li-4", link: "4" },
  ];

  const selectMenuHandler = (index) => {
    // parameter로 현재 선택한 인덱스 값을 전달해야 하며, 이벤트 객체(event)는 쓰지 않는다
    // 해당 함수가 실행되면 현재 선택된 Tab Menu 가 갱신.
    setData(index);
  };

  //pagecount
  const pagecount = [
    { name: "10", id: "select-1", value: "10" },
    { name: "30", id: "select-2", value: "30" },
    { name: "50", id: "select-3", value: "50" },
  ];

  const handlePagecountChange = (event) => {
    setPageCount(event.target.value);
    console.log(data);
    console.log(pageCount);
    const newPath = `/board?b_type=${data}&viewCnt=${event.target.value}`;
    history(newPath);
  };

  //글쓰기 페이지로 이동
  const moveWriteForm = () => {
    window.location.href = "/";
  };

  return (
    <div>
      <div className="write_form_wrap">
        <div>
          <ul className="tabs">
            {tabEvent.map((el, index) => (
              <Link
                key={el.id}
                to={`/board?b_type=${el.link}&viewCnt=${pageCount}`}
              >
                <li
                  className={index === data ? "tab-link current" : "tab-link"}
                  id={el.id}
                  onClick={() => selectMenuHandler(index)}
                  style={{ color: "black" }}
                >
                  {el.name}
                </li>
              </Link>
            ))}
          </ul>
        </div>

        <div className="write_form">
          <button
            type="submit"
            id="write-top"
            className="btn-board-top"
            onClick={moveWriteForm}
          >
            <img
              src={"https://cdn-icons-png.flaticon.com/512/5218/5218705.png"}
              id="img_write"
            />
            글쓰기
          </button>
        </div>
      </div>
      <div className="menu_select">
        <div className="text">
          <select
            className="form-select form-select-sm"
            id="view-select"
            aria-label=".form-select-sm example"
            onChange={handlePagecountChange}
          >
            {pagecount.map((sl) => {
              return (
                <option key={sl.id} id={sl.id} value={sl.value}>
                  {sl.name}
                </option>
              );
            })}
          </select>
        </div>
      </div>
    </div>
  );
}

export default Tabs;
