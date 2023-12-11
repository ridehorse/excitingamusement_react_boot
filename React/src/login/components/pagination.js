import React from "react";
import Pagination from "react-bootstrap/Pagination";

import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";

const paging = (prop) => {
  const startPage = prop.pageMaker.startPage;
  const endPage = prop.pageMaker.endPage;
  const pageNum = prop.pageMaker.pageNum;
  const next = prop.pageMaker.next;
  const total = prop.pageMaker.total;
  const sort = prop.sort;

  const lastPage = Math.ceil(total / 10);

  let active = pageNum;
  let items = [];
  for (let number = startPage; number <= endPage; number++) {
    items.push(
      <Pagination.Item
        key={number}
        active={number === active}
        href={`/writeList/${number}?sort=${sort}`}
        style={{ paddingLeft: "13px", paddingRight: "20px" }}
      >
        {number}
      </Pagination.Item>
    );
  }
  return (
    <Row className="mt-4 mb-4">
      <Col className="d-flex justify-content-center">
        <div className="mx-auto">
          <Pagination style={{ marginLeft: "0px" }}>
            <Pagination.First href={`/writeList/1?sort=${sort}`} />
            {pageNum === 1 ? null : (
              <Pagination.Prev
                href={`/writeList/${pageNum - 1}?sort=${sort}`}
              />
            )}
            {items}
            {next ? (
              <Pagination.Next
                href={`/writeList/${endPage + 1}?sort=${sort}`}
              />
            ) : null}
            <Pagination.Last href={`/writeList/${lastPage}?sort=${sort}`} />
          </Pagination>
        </div>
      </Col>
    </Row>
  );
};

export default paging;
