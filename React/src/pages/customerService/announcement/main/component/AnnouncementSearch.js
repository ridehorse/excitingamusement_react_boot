import styles from "../announcement.module.css";
function AnnouncementSearch({ searchData, setSearchData, setSearchCheck }) {
  const changeSearchData = (e) => {
    let searchValue = e.target.value;
    setSearchData(searchValue);
  };

  const searchCheckBtn = (e, check) => {
    if (check === 1) {
      let searchValue = e.target.value;
      setSearchCheck(1);
      window.location.href = `/announcement?pageNum=1&search=${searchValue}`;
    } else {
      setSearchCheck(1);
      let searchValue = e.target.previousElementSibling.value;
      window.location.href = `/announcement?pageNum=1&search=${searchValue}`;
    }
  };

  return (
    <>
      <select
        name="select"
        className={styles.search_select}
        id="search_select"
        style={{ display: "none" }}
      >
        <option value="c_title">제목</option>
      </select>

      <label htmlFor="search" className={styles.blind}>
        공지사항 내용 검색
      </label>
      <input
        id="search"
        className={styles.text}
        type="search"
        name="search"
        value={searchData != null ? searchData : ""}
        onChange={changeSearchData}
        onKeyPress={(event) => {
          if (event.key === "Enter") {
            searchCheckBtn(event, 1);
          }
        }}
      ></input>
      <button
        type="button"
        className={[styles.btn, styles.btnSearch].join(" ")}
        onClick={(event) => {
          searchCheckBtn(event, 2);
        }}
        style={{
          backgroundColor: '#555555',
          color: '#fff',
          border_radius: 15,

        }}
      >
        검색
      </button>
    </>
  );
}

export default AnnouncementSearch;
