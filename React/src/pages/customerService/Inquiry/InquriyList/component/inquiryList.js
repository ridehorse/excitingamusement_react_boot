import React, { useEffect, useRef, useState } from "react";
import axios from "axios";
import { Link, useLocation } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import PagingSearch from "./pagingSearch";
import styles from "../inquiry.module.css";

function InquiryList() {
  const [data, setData] = useState([]);
  const [selectSearchType, setSelectSearchType] = useState("b_title");
  const [searchValue, setSearchValue] = useState();
  const totalPages = useRef(0);
  const pageNumber = useRef(0);
  const location = useLocation();

  useEffect(() => {
    const fetchData = () => {
      const addressParams = new URLSearchParams(location.search);
      const pageNum = addressParams.get("pageNum");
      const searchParams = addressParams.get("search");
      let type = selectSearchType;
      if (addressParams.get("type") !== null) {
        type = addressParams.get("type");
      }
      pageNumber.current = pageNum;
      setSelectSearchType(type);
      setSearchValue(searchParams);
      getBoardList(pageNum, searchParams, type);
    };
    fetchData();
  }, [location]);


  const getBoardList = (pageNum, searchParams, type) => {
    let search = null;
    const member_id = sessionStorage.getItem("MEMBER_ID");

    if (pageNum === null) {
      pageNum = 1;
      pageNumber.current = pageNum;
    }

    if (searchParams !== null && searchParams !== undefined) {
      search = searchParams;
    }

    const requestOptions = {
      method: "GET",
      url: "http://localhost:8080/customer/inquiryList",
      headers: {
        "Content-Type": "application/json",
      },

      params: {
        pageNum: pageNum,
        type: type,
        search: search,
        member_id: member_id
      },
    };

    const getInquiryList = async () => {
      try {
        const response = await axios(requestOptions);
        const data = response.data;
        totalPages.current = data.totalPages;
        setData(data.content);
      } catch (error) {
      }
    };
    getInquiryList();
  };

  const renderPostDate = (item) => {
    const separator = [".", ".", " ", ":", ":"];

    const postDate = item.postDate;

    // 두 자릿수로 맞춰주는 함수
    const padNumber = (number) => {
      return String(number).padStart(2, "0");
    };

    const date = new Date(postDate);
    const year = date.getFullYear();
    const month = padNumber(date.getMonth() + 1);
    const day = padNumber(date.getDate());
    const hour = padNumber(date.getHours());
    const minute = padNumber(date.getMinutes());

    // 날짜 형식을 조합하여 반환
    const formattedDate = `${year}${separator[0]}${month}${separator[1]}${day} ${hour}${separator[3]}${minute}`;

    return <React.Fragment>{formattedDate}</React.Fragment>;
  };

  return (
    <div>
      <table className={styles.board_table} style={{ maxWidth: 1300, textAlign: "center", marginLeft: 100, margin: 'auto' }}>
        <thead>
          <tr style={{ borderTop: '1px solid #B0B0B0', borderBottom: '1px solid #E0E0E0' }}>
            <th scope="col" className="th-num" style={{ width: "5%", padding: 15 }}>
              번호
            </th>
            <th scope="col" className="th-num" style={{ width: "10%" }}>
              분류
            </th>
            <th scope="col" className="th-title" style={{ width: "45%" }}>
              제목
            </th>
            <th scope="col" className="th-title" style={{ width: "10%" }}>
              작성자
            </th>
            <th scope="col" className="th-date" style={{ width: "30%" }}>
              등록일
            </th>
          </tr>
        </thead>

        <tbody className={styles.boardList} id="boardList">
          {/* 합쳐진 데이터를 렌더링하는 부분 */}
          {/* 각 필드에 대한 데이터를 출력 */}
          {data.map(
            (item, index) =>
              item.inquiry_num && (
                <tr key={index}>
                  <td>{item.inquiry_num}</td>
                  <td>{item.b_type}</td>
                  <td style={{ padding: 15 }}>
                    <Link to={`/inquiryDetail?inquiry_num=${item.inquiry_num}`}>
                      {item.b_title}
                    </Link>
                  </td>
                  <td>{item.member_id}</td>
                  <td>{renderPostDate(item)}</td>
                </tr>
              )
          )}
        </tbody>
      </table>

      <PagingSearch
        data={data}
        setData={setData}
        selectSearchType={selectSearchType}
        setSelectSearchType={setSelectSearchType}
        searchValue={searchValue}
        setSearchValue={setSearchValue}
        totalPages={totalPages}
        pageNumber={pageNumber}
      />
    </div>
  );
}

export default InquiryList;
