import React from "react";
import AnnouncementSearch from "./AnnouncementSearch";
import PagingNumberLogic from "./PagingNumberLogic";
import styles from "../announcement.module.css";

function PagingSearch({
  setSearchCheck,
  searchData,
  setSearchData,
  pageNumber,
  totalPages,
}) {
  // 글쓰기 이동
  const moveWriteForm = () => {
    window.location.href = "/addAnnouncement";
  };

  // 페이징 로직
  //   const createPageLinks = () => {
  //     return(

  //     );
  //   };

  return (
    <>
      <div className={styles.page_wrap}>
        {" "}
        {/* 페이지 네이션 출력 부분 */}
        <span className={styles.page_nation} style={{ marginRight: 300 }}>
          <PagingNumberLogic
            pageNumber={pageNumber}
            totalPages={totalPages}
            searchValue={searchData}
          />
        </span>
        {/* 글쓰기 버튼 */}
        {sessionStorage.getItem("ADMIN") === null ? (
          ""
        ) : (
          <span
            className={[styles.write_bottom_wrap, styles.top].join(" ")}
            style={{ float: "right" }}
          >
            <button
              type="submit"
              id="write_bottom"
              className={[styles.btn, styles.btn_blue, styles.write_bottom].join(" ")}
              onClick={moveWriteForm}
              style={{
                backgroundColor: '#4aa8d8',
                color: '#fff',
                border_radius: 15,
                paddingRight: 30,
                paddingLeft: 30,
                paddingTop: 10,
                paddingBottom: 10
              }}
            >
              글쓰기
            </button>
          </span>
        )}
      </div >
      <div style={{ clear: "both" }}></div> {/* 검색 */}
      <div className={styles.anno_search}>
        <div className={styles.anno_container}>
          <div className={styles.search_window}>
            <div className={styles.search_wrap}>
              <AnnouncementSearch
                searchData={searchData}
                setSearchData={setSearchData}
                setSearchCheck={setSearchCheck}
              />
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default PagingSearch;
