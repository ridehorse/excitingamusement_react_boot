import React, { useEffect, useState } from "react";
import axios from "axios";
// import "./mypoint.css";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";
import { Col, Container, Row } from "react-bootstrap";
import MyNavbar from "../login/components/MyNavBar";

function Mypoint() {
  const [data, setData] = useState({ orderlist: [], mypoint: [] });
  useEffect(() => {
    fetchData();
  }, []);
  const member_id = sessionStorage.getItem("MEMBER_ID");

  const fetchData = async () => {
    try {
      const response = await axios.get(
        `http://localhost:8080/mypoint?member_id=${member_id}`
      );
      const data1 = response.data;
      setData(data1);
    } catch (error) {
      console.error(error);
    }
  };
  console.log(data);
  const refund = () => {
    console.log("a");
  };

  // Locale 설정
  const toKRWString = (number) => {
    return new Intl.NumberFormat("ko-KR", {
      style: "currency",
      currency: "KRW",
    }).format(number);
  };

  return (
    <Container>
      <Row>
        <MyNavbar />
        <Col xs={9} className="my-5">
          <div className="container custom-main-padding border-bottom mt-5">
            <h2 className="mb-5">
              사용 가능한 포인트는{" "}
              {toKRWString(data.mypoint[0]?.sum_point ?? 0)} 포인트 입니다.
            </h2>
            <hr />
            <h4 className="mb-3">포인트 적립 내역</h4>
            {Object.values(
              data.orderlist.reduce((acc, d) => {
                if (!acc[d.order_id]) {
                  acc[d.order_id] = [];
                }
                acc[d.order_id].push(d);
                return acc;
              }, {})
            )
              .sort(
                (a, b) => new Date(b[0].order_date) - new Date(a[0].order_date)
              )
              .map((orders, index) => (
                <div className="row" key={`${orders[0].order_date}-${index}`}>
                  {orders[0].quantity !== 0 && (
                    <>
                      <div className="w-100"></div>
                      <h4 className="mb-3">
                        주문번호: {orders[0].order_id}
                        {orders[0].checkorder ? (
                          <button
                            className="btn btn-success"
                            disabled={
                              orders[0].checkorder || orders[0].checkrefund
                            }
                          >
                            구매 확정 완료
                          </button>
                        ) : orders[0].checkrefund ? (
                          <button
                            className="btn btn-danger"
                            disabled={
                              orders[0].checkorder || orders[0].checkrefund
                            }
                          >
                            환불 처리 완료
                          </button>
                        ) : (
                          <></>
                        )}
                      </h4>
                      {orders.map((d, idx) => (
                        <div
                          className="col-md-4 mb-5 "
                          key={`${orders[0].order_id}-${d.ticket_name}-${idx}`}
                        >
                          <div className="card">
                            <div className="card-body">
                              <h5 className="card-title">
                                주문번호 : {d.order_id}
                              </h5>
                              <p className="card-text">{d.a_name}</p>
                              <p className="card-text">{d.promotion_name}</p>
                              <p className="card-text">{d.ticket_name}</p>
                              <p className="card-subtitle mb-2 text-muted">
                                {toKRWString(d.ticket_price * (1 - d.discount))}{" "}
                                * {d.quantity}
                              </p>
                              <input
                                id="myPointInput"
                                className="MyPoint"
                                type="hidden"
                                value={
                                  d["ticket_price"] *
                                  (1 - d["discount"]) *
                                  d["quantity"] *
                                  0.05
                                }
                              />
                              {d.checkorder && d.use_point !== null && (
                                <>
                                  <p className="card-text">
                                    결제금액 :{" "}
                                    {toKRWString(
                                      d.ticket_price *
                                        (1 - d.discount) *
                                        d.quantity -
                                        d.use_point
                                    )}
                                  </p>
                                  <p className="text-danger">
                                    포인트 사용 : {toKRWString(d.use_point)}
                                  </p>
                                </>
                              )}
                              {d.checkorder &&
                                (d.use_point === null || d.use_point === 0) && (
                                  <p className="card-text">
                                    결제금액 :{" "}
                                    {toKRWString(
                                      d.ticket_price *
                                        (1 - d.discount) *
                                        d.quantity
                                    )}
                                  </p>
                                )}
                              {d.checkrefund && (
                                <del>
                                  <p className="card-text">
                                    결제금액 :{" "}
                                    {toKRWString(
                                      d.ticket_price *
                                        (1 - d.discount) *
                                        d.quantity
                                    )}
                                  </p>
                                </del>
                              )}
                              {d.checkorder && (
                                <p className="text-danger">
                                  포인트 적립 :{" "}
                                  {toKRWString(
                                    d.ticket_price *
                                      (1 - d.discount) *
                                      d.quantity *
                                      0.05
                                  )}
                                </p>
                              )}
                              {d.checkrefund && (
                                <del>
                                  <p className="text-danger">
                                    포인트 적립 :{" "}
                                    {toKRWString(
                                      d.ticket_price *
                                        (1 - d.discount) *
                                        d.quantity *
                                        0.05
                                    )}
                                  </p>
                                </del>
                              )}
                              <p className="card-text">
                                구매 날짜 : {d.order_date}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </>
                  )}
                  <div></div>
                </div>
              ))}
          </div>
        </Col>
      </Row>
    </Container>
  );
}

export default Mypoint;
