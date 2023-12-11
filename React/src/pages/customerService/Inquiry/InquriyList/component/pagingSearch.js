import PagingNumberLogic from "./PagingNumberLogic";
import styles from "../inquiry.module.css";

function PagingSearch({
  searchValue,
  selectSearchType,
  setSearchValue,
  totalPages,
  pageNumber,
  setSelectSearchType,
}) {
  //글쓰기 이동
  const moveWriteForm = () => {
    window.location.href = "/insertInquiry";
  };

  const changeSelectType = (e) => {
    setSelectSearchType(e.target.value);
  };

  const changeSearchValue = (e) => {
    setSearchValue(e.target.value);
  };

  const searchMove = () => {
    window.location.href = `/inquiry?pageNum=1&type=${selectSearchType}&search=${searchValue}`;
  };

  return (
    <>
      <div className={styles.page_wrap} style={{ textAlign: "center" }}>
        {/* 페이지 네이션 출력 부분 */}
        <span className={styles.page_nation} style={{ marginTop: 30 }} >
          <PagingNumberLogic
            totalPages={totalPages}
            pageNumber={pageNumber}
            searchValue={searchValue}
          />
        </span>

        {/* 글쓰기 버튼 */}
        <span className={styles.write_bottom_wrap} style={{ float: "right", marginRight: 200 }}>
          <button
            type="submit"
            id="write-bottom"
            className={[styles.btn, styles.btn_blue, styles.top].join(" ")}
            onClick={moveWriteForm}
            style={{
              backgroundColor: '#4aa8d8',
              color: '#fff',
              borderRadius: 5,
              paddingRight: 25,
              paddingLeft: 25,
              paddingTop: 5,
              paddingBottom: 5,
              margin: 10
            }}
          >
            글쓰기
          </button>
        </span>
      </div>



      <div className={styles.board_search} id="board-search">
        <div className={styles.container}>
          <div className={styles.search_window} style={{ maxWidth: 1300, marginLeft: 100, marginTop: 50 }}>
            <div className={styles.search_wrap} >
              <div style={{ display: 'flex' }}>
                <select
                  name="select"
                  className={styles.board_selectField}
                  id="search_select"
                  value={selectSearchType}
                  onChange={changeSelectType}
                  style={{
                    width: 100,
                    height: 40,
                    textAlign: 'center',
                    fontSize: 14,
                    marginRight: 10
                  }}
                >
                  <option value="b_title">제목</option>
                  <option value="b_content">내용</option>
                  <option value="member_id">작성자</option>
                </select>

                <input
                  id="search"
                  type="search"
                  name="search"
                  value={searchValue}
                  onChange={changeSearchValue}
                  style={{
                    width: 400,
                    height: 40,
                    marginRight: 10
                  }}
                  onKeyPress={(event) => {
                    if (event.key === 'Enter') {
                      searchMove();
                    }
                  }}
                />

                <button
                  type="button"
                  className={[styles.btn, styles.btn_search].join(' ')}
                  onClick={searchMove}
                  style={{
                    backgroundColor: '#555555',
                    color: '#fff',
                    width: 65,
                    height: 40,
                    lineHeight: '40px'
                  }}
                >
                  검색
                </button>
              </div>
            </div>
          </div>
        </div>
      </div >
    </>
  );
}

export default PagingSearch;
