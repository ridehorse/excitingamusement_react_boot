import "../../css/FAQ/FAQ.css";

const Pagination = ({ totalPages, currentPage, setCurrentPage }) => {
  // 페이지 번호 변경 핸들러
  const handlePageChange = (newPage) => {
    setCurrentPage(newPage);
  };

  // 페이지 번호 목록 생성 및 렌더링
  const renderPageNumbers = () => {
    const pageNumbers = [];
    for (let i = 1; i <= totalPages; i++) {
      // 현재 페이지와 일치하는 버튼에 대해 클래스를 추가합니다.
      const buttonClass = currentPage === i ? "active-page" : "";

      pageNumbers.push(
        <button
          key={i}
          className={buttonClass}
          onClick={() => handlePageChange(i)}
        >
          {i}
        </button>
      );
    }
    return pageNumbers;
  };

  return (
    <div className="page_nation_wrap">
      <div className="page_nation">{renderPageNumbers()}</div>
    </div>
  );
};

export default Pagination;
