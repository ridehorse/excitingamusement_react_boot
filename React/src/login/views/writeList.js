import React, { useEffect, useState } from "react";
import { call } from "../service/ApiService";

import Container from "react-bootstrap/Container";
import Row from "react-bootstrap/Row";
import Col from "react-bootstrap/Col";
import AnswerListTable from "../components/AnswerListTable";
import Paging from "../components/pagination";
import { useParams } from "react-router-dom";
import { useLocation } from "react-router-dom";

const WriteList = (props) => {
  const [lists, setLists] = useState([]);
  const [pageMaker, setPageMaker] = useState([]);
  const [total, setTotal] = useState([]);

  const kakao_name = sessionStorage.getItem("KAKAO_NAME");
  const git_id = sessionStorage.getItem("GIT_ID");
  const member_id = sessionStorage.getItem("MEMBER_ID");

  // writeList/12 에서 12를 받아온다.
  const { id } = useParams();

  // ?sort=1 같은 파라미터 값을 가져온다.
  const location = useLocation();
  const queryParams = new URLSearchParams(location.search);
  const sort = queryParams.get("sort");
  console.log("sort :" + sort);

  useEffect(() => {
    call(
      `/mypage/writeList/${id}?member_id=${member_id}&sort=${sort}`,
      "GET",
      null
    ).then((response) => {
      console.log(response);

      const lists = response.list;
      const pageMaker = response.pageMaker;
      const total = response.total;

      setLists(lists);
      setPageMaker(pageMaker);
      setTotal(total);

      console.log(lists);
    });
  }, []);

  function handleClickWritePlace(list) {
    if (list.category === "문의게시판") {
      window.location.href = "/inquiryDetail?inquiry_num=" + list.view_id;
    }
    if (list.category === "게시판 댓글") {
      window.location.href = "/detail?board_id=" + list.view_id;
    }
    if (list.category === "자유게시판") {
      window.location.href = "/detail?board_id=" + list.view_id;
    }
  }

  return (
    <Col xs={9}>
      <div className="d-flex justify-content-center">
        <div style={{ width: "540px" }}>
          <Container>
            <Row
              className="mx-1 my-5 rounded-0"
              style={{ backgroundColor: "rgba(173, 216, 270, 30)" }}
            >
              <Col className="">
                <div
                  className="h2 text-center pt-2"
                  style={{ color: "white", fontWeight: "500" }}
                >
                  내 게시글/댓글
                </div>
              </Col>
            </Row>
            <Row className="mb-2 mx-1">
              <div style={{ fontSize: "14px" }}>
                {kakao_name || git_id || pageMaker.cri?.member_id}
                님의 게시글 모음
              </div>
            </Row>
            <Row className="mb-3 border-bottom border-2 pb-1 mx-1">
              <div style={{ fontSize: "10px" }}>
                * 총 {total}개의 게시글 작성
              </div>
            </Row>
            <AnswerListTable sort={sort} />
            <Row className="mb-4"></Row>

            <div className="mx-2">
              {lists.map((list, index) => (
                <div
                  className="mx-1 border-bottom border-1 pb-3 mb-3"
                  key={index}
                >
                  <Row className="mb-4">
                    <Col style={{ fontSize: "14px", fontWeight: "600" }} sm={9}>
                      {list.b_title}
                    </Col>
                    <Col
                      className="text-center pt-1"
                      sm={3}
                      style={{ fontSize: "12px", fontWeight: "600" }}
                    >
                      {list.category}
                    </Col>
                  </Row>
                  <Row className="mb-3">
                    <Col style={{ fontSize: "13px" }} sm={9}>
                      <div
                        dangerouslySetInnerHTML={{ __html: list.b_content }}
                      ></div>
                    </Col>
                    <Col></Col>
                  </Row>
                  <Row>
                    <Col style={{ fontSize: "11px" }} sm={4}>
                      {list.postdate}
                    </Col>
                    <Col sm={8} className="d-flex justify-content-end">
                      <input
                        className="locateBtn border border-info rounded-0"
                        value="작성한곳으로 이동"
                        style={{ height: "30px", fontSize: "14px" }}
                        type="button"
                        onClick={() => handleClickWritePlace(list)}
                      />
                    </Col>
                  </Row>
                </div>
              ))}
            </div>

            <Row>
              <Col>
                <Paging pageMaker={pageMaker} sort={sort} />
              </Col>
            </Row>
          </Container>
        </div>
      </div>
    </Col>
  );
};

export default WriteList;
