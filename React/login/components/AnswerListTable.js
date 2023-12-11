import React from "react";
import Nav from "react-bootstrap/Nav";

const AnswerListTable = (props) => {
  const { sort } = props;
  console.log("~~~sort :" + sort);

  return (
    <Nav
      variant="tabs"
      defaultActiveKey={
        sort === "ASC" ? "/writeList/1?sort=ASC" :  "/writeList/1?sort=DESC"
      }
    >
      <Nav.Item>
        <Nav.Link href="/writeList/1?sort=DESC">최신순</Nav.Link>
      </Nav.Item>
      <Nav.Item>
        <Nav.Link href="/writeList/1?sort=ASC">과거순</Nav.Link>
      </Nav.Item>
    </Nav>
  );
};

export default AnswerListTable;
