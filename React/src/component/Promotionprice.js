import axios from "axios";
import { Link, useLocation } from "react-router-dom";
import React, { useState, useEffect } from "react";
import "./Promotionprice.css";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";

function useQuery() {
  return new URLSearchParams(useLocation().search);
}
const member_id = sessionStorage.getItem("MEMBER_ID");

function Promotionprice() {
  const query = useQuery();
  const promotion_id = query.get("promotion_id");

  const [data, setData] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get(
          `http://localhost:8080/promotionprice?promotion_id=${promotion_id}`
        );
        setData(response.data);
        console.log(response);
      } catch (error) {
        console.log(error);
      }
    };

    fetchData();
  }, [promotion_id]);

  return (
    <div>
      <div className="container mt-5 text-center">
        <img
          src={data[0]?.promotion_img}
          alt="Promotion Image1"
          className="promotion-img"
        />
        <div className="container mt-5">
          <div className="jumbotron">
            <h1 className="promotion-title display-4 mb-4">
              {data[0]?.promotion_content}
            </h1>
            <p className="promotion-desc mb-5">{data[0]?.promotion_name}</p>
            <h2 className="ticket-title">티켓 가격</h2>
            <table className="table table-striped">
              <tbody>
                {data.map((d, index) => (
                  <tr key={index}>
                    <td>{d.ticket_name}</td>
                    <td>
                      정상가 :{" "}
                      <del>
                        {Intl.NumberFormat("ko-KR", {
                          style: "currency",
                          currency: "KRW",
                        }).format(d.ticket_price)}
                      </del>
                    </td>
                    <td>
                      할인가 :{" "}
                      {Intl.NumberFormat("ko-KR", {
                        style: "currency",
                        currency: "KRW",
                      }).format(d.ticket_price * (1 - d.discount))}
                    </td>
                    <td>
                      할인율 :{" "}
                      {Intl.NumberFormat("ko-KR", {
                        style: "percent",
                        minimumFractionDigits: 2,
                        maximumFractionDigits: 2,
                      }).format(d.discount)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <button className="learn-more-btn btn-lg" type="button">
              <Link
                to={`/order?promotion_id=${data[0]?.promotion_id}&member_id=${member_id}`}
              >
                구매 하러 가기
              </Link>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Promotionprice;
