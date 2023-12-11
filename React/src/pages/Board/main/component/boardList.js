import { useEffect, useState } from "react";
import $ from "jquery";
import axios from "axios";
import { Link, useLocation } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";

function BoardList() {
  const [data, setData] = useState([]);
  const location = useLocation();

  useEffect(() => {
    getBoardList();
  }, [location.search]);

  const getBoardList = () => {
    const selectValue = $("select[name=select]").val();
    const searchValue = $("input[name=search]").val();

    console.log(location.search);
    const searchParams = new URLSearchParams(location.search);

    //탭으로 분류
    const b_typeVaule = searchParams.get("b_type");
    let pageCount = searchParams.get("viewCnt");
    console.log(pageCount);

    if (pageCount == null) {
      pageCount = 10;
      console.log(pageCount);
    }
    console.log(pageCount);

    const requestOptions = {
      method: "GET",
      url: "http://localhost:8080/board/boardList",
      headers: {
        "Content-Type": "application/json",
      },

      params: {
        select: selectValue,
        search: searchValue,
        b_type: b_typeVaule,
        viewCnt: pageCount,
      },
    };

    const fetchData2 = async () => {
      try {
        const response = await axios(requestOptions);
        const data = response.data;
        console.log(data);
        setData(data);
      } catch (error) {
        console.log("http error");
        console.log(error);
      }
    };
    fetchData2();
  };

  return (
    <div>
      <table className="board-table">
        <thead>
          <tr>
            <th scope="col" className="th-num" style={{ width: "5%" }}>
              번호
            </th>
            <th scope="col" className="th-num" style={{ width: "10%" }}>
              분류
            </th>
            <th scope="col" className="th-title" style={{ width: "30%" }}>
              제목
            </th>
            <th scope="col" className="th-member" style={{ width: "10%" }}>
              작성자
            </th>
            <th scope="col" className="th-date" style={{ width: "30%" }}>
              등록일
            </th>
            <th scope="col" className="th-date" style={{ width: "5%" }}>
              추천수
            </th>
            <th scope="col" className="th-date" style={{ width: "5%" }}>
              조회수
            </th>
          </tr>
        </thead>

        <tbody id="boardList">
          {/* 합쳐진 데이터를 렌더링하는 부분 */}
          {data.map((item) => (
            <tr key={item.board_id}>
              {/* 각 필드에 대한 데이터를 출력 */}
              <td>{item.board_id}</td>
              <td>{item.b_type}</td>
              <td>
                <Link to={`/detail?board_id=${item.board_id}`}>
                  {item.b_title}
                </Link>
              </td>
              <td>{item.member_id}</td>
              <td>{item.postdate}</td>
              <td>{item.favorite}</td>
              <td>{item.visitcount}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default BoardList;
