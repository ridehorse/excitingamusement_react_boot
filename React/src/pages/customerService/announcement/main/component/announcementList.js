import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { Link, useLocation } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import PagingSearch from "./pagingSearch";
import styles from "../announcement.module.css";

function AnnouncementList() {
  const [data, setData] = useState([]);
  const pageNumber = useRef(1);
  const totalPages = useRef(0);
  const [searchData, setSearchData] = useState("");
  const [searchCheck, setSearchCheck] = useState(0);
  const location = useLocation();

  useEffect(() => {
    RenderingData();
  }, []);

  useEffect(() => {
    RenderingData();
  }, [searchCheck]);

  const RenderingData = () => {
    const addressParams = new URLSearchParams(location.search);

    let PageNum = addressParams.get("pageNum");
    let searchParam = addressParams.get("search");

    if (PageNum === null) {
      PageNum = 1;
    }

    if (searchParam !== null) {
      setSearchData(searchParam);
    } else {
      searchParam = "";
      setSearchData(searchParam);
    }

    if (searchCheck === 1) {
      PageNum = 1;
    }

    pageNumber.current = PageNum;
    getBoardList(PageNum, searchParam);
  };

  const getBoardList = (PageNum, searchParam) => {
    if (PageNum === null || PageNum === undefined) {
      PageNum = 1;
    }

    const fetchData2 = async () => {
      await axios
        .get("http://localhost:8080/customer/announcement", {
          params: {
            pageNum: PageNum,
            search: searchParam,
          },
        })
        .then((response) => {
          const data = response.data;
          totalPages.current = data.totalPages;
          setData(data.content);
        })
        .catch((error) => {
          // window.alert("정보 불러오기 실패!");
          // window.location.href = "/";
        });
    };
    fetchData2();
  };

  const conversionPostdate = (item) => {
    let postdate = item.postdate;
    let formattedPostDate = postdate
      .replace("T", " ")
      .substring(0, 16)
      .replace(/-/g, ".");

    return <td>{formattedPostDate}</td>;
  };

  return (
    <div>
      <table className={styles.anno_table}>
        <thead>
          <tr>
            <th scope="col" className={styles.th_num} style={{ width: "5%" }}>
              번호
            </th>
            <th scope="col" className={styles.th_num} style={{ width: "15%" }}>
              분류
            </th>
            <th
              scope="col"
              className={styles.th_title}
              style={{ width: "25%" }}
            >
              제목
            </th>
            <th scope="col" className={styles.th_date} style={{ width: "30%" }}>
              등록일
            </th>
          </tr>
        </thead>

        <tbody className={styles.anno_boardList}>
          {/* 합쳐진 데이터를 렌더링하는 부분 */}
          {/* 각 필드에 대한 데이터를 출력 */}
          {data.map(
            (item, index) =>
              item.announcement_num && (
                <tr key={index}>
                  <td>{item.announcement_num}</td>
                  <td>{item.c_type}</td>
                  <td>
                    <Link
                      to={`/announcementDetail?announcement_num=${item.announcement_num}`}
                    >
                      {item.c_title}
                    </Link>
                  </td>
                  {conversionPostdate(item)}
                </tr>
              )
          )}
        </tbody>
      </table>

      <div style={{ marginRight: 100 }}>
        <PagingSearch
          data={data}
          pageNumber={pageNumber}
          totalPages={totalPages}
          searchData={searchData}
          setSearchData={setSearchData}
          setSearchCheck={setSearchCheck}
        />
      </div>
    </div>
  );
}

export default AnnouncementList;
