import axios from "axios";
import { useNavigate, useLocation } from "react-router-dom";
import React, { useState, useEffect } from "react";
import "./order.css";
import "bootstrap/dist/css/bootstrap.min.css";
//import "bootstrap-icons/font/bootstrap-icons.css";

function useQuery() {
  return new URLSearchParams(useLocation().search);
}

const Order = () => {
  const navigate = useNavigate();
  const query = useQuery();
  const promotion_id = query.get("promotion_id");
  const member_id = sessionStorage.getItem("MEMBER_ID");
  const [sum, setSum] = useState(0);
  const [mypoint, setMyPoint] = useState(0);
  const [data, setData] = useState({ price: [], mypoint: [] });
  const [isDataLoaded, setIsDataLoaded] = useState(false);
  const [count, setCount] = useState(0);

  useEffect(() => {
    fetchData1();
  }, []);

  const fetchData1 = async () => {
    try {
      const response = await axios.get(
        `http://localhost:8080/order?promotion_id=${promotion_id}&member_id=${member_id}`
      );
      const data1 = response.data;

      if (data1.mypoint.length === 0) {
        data1.mypoint.push({
          sum_point: 0,
          m_point: null,
          point_id: 0,
          order_id: 0,
          member_id: null,
        });
      }

      setMyPoint(data1.mypoint[0]["sum_point"]);
      setData(data1);
      setIsDataLoaded(true);
      console.log(member_id + "ididid");
      console.log(response);
      console.log(mypoint + "@@mypointmypoint");
      console.log(data1.mypoint + "@@mypointmypoint");
    } catch (error) {
      console.error(error);
    }
  };

  const countTicket = (type, ticketId) => {
    const row = document
      .querySelector(`.table-row .ticket-id[value="${ticketId}"]`)
      .closest(".table-row");
    const numbox = row.querySelector(".numbox");

    if (type === "plus" && parseInt(numbox.value) < 10) {
      setCount({ ...count, [ticketId]: (count[ticketId] || 0) + 1 });
    } else if (type === "minus" && parseInt(numbox.value) > 0) {
      setCount({ ...count, [ticketId]: (count[ticketId] || 0) - 1 });
    }
  };

  const countClick = (type, ticketId) => {
    const row = document
      .querySelector(`.ticket-id[value="${ticketId}"]`)
      .closest(".table-row");
    const numbox = row.querySelector(".numbox");

    if (type === "plus" && count >= 10) {
      return;
    } else if (type === "minus" && count <= 0) {
      return;
    }

    countTicket(type, ticketId);

    const priceValue = parseInt(
      row.querySelector(".price").textContent.replace(/[^0-9]/g, "")
    );
    console.log(count + "@@@count");

    const newTicketCount =
      type === "minus"
        ? (count[ticketId] || 1) - 1
        : (count[ticketId] || 0) + 1;
    if (row.querySelector(".ticket-id").value !== null) {
      if (newTicketCount > 10) {
        return;
      }
      const dataa = `<td>${priceValue * newTicketCount}</td>`;
      row.querySelector(".total").innerHTML = dataa;
    }

    updateSum();
  };

  const updateSum = () => {
    let totalSum = 0;
    const total = document.querySelectorAll(".total");
    total.forEach((element) => {
      const value = element.textContent.replace(/[^0-9]/g, "");
      totalSum += value ? parseInt(value) : 0;
    });
    setSum(totalSum);
  };
  const handlePointChange = (e) => {
    const value = e.target.value;
    if (value < 0 || value > data.mypoint[0]["sum_point"]) {
      alert("사용가능한 포인트가 아닙니다.");
      setMyPoint(data.mypoint[0]["sum_point"]);
    } else {
      setMyPoint(value);
    }
  };

  const handleBuyClick = () => {
    if (window.confirm("구매 하시겠습니까?")) {
      const myArray = [];
      const usePoint = mypoint;
      const member_id = sessionStorage.getItem("MEMBER_ID");
      const tableRows = document.querySelectorAll(".table-row");
      tableRows.forEach((row) => {
        const myMap = new Map();
        const ticketId = row.querySelector(".ticket-id").value;
        const numbox = row.querySelector(".numbox");
        myMap.set("ticket_id", ticketId);
        myMap.set("quantity", numbox.value);
        myArray.push(myMap);
      });

      const myJSON = JSON.stringify(
        myArray.map((obj) => ({
          ticket_id: obj.get("ticket_id"),
          quantity: obj.get("quantity"),
        }))
      );

      console.log(myJSON + "myJSON");

      //여기에 axios 요청 만들기
      const url = "http://localhost:8080/order";
      const dataToSubmit = {
        myJSON: myJSON,
        use_point: Number(usePoint).toFixed(2),
        member_id: member_id,
      };

      axios
        .post(url, dataToSubmit)
        .then((response) => {
          console.log(response.data);
          alert("구매해 주셔서 감사합니다!");

          navigate("/promotion");
        })
        .catch((error) => {
          console.error("Error occurred during request:", error);
        });
    }
  };

  return (
    <div className="container">
      <form action="/" method="post">
        <div className="product">
          <img
            src={isDataLoaded ? data.price[0]["promotion_img"] : ""}
            alt="Product Image1"
          />
          <div>
            <div className="name">
              {isDataLoaded ? data.price[0]["promotion_name"] : ""}
            </div>
            <div className="description">
              {isDataLoaded ? data.price[0]["promotion_content"] : ""}
            </div>
          </div>
        </div>
        <table>
          <thead>
            <tr>
              <th>행사명</th>
              <th>상품명</th>
              <th>가격</th>
              <th>수량</th>
              <th>합계</th>
            </tr>
          </thead>
          <tbody>
            {data.price.map((d) => (
              <tr className="table-row" key={d.ticket_id}>
                <td>{d.promotion_name}</td>
                <td>{d.ticket_name}</td>
                <td className="price">
                  {new Intl.NumberFormat("ko-KR", {
                    style: "currency",
                    currency: "KRW",
                  }).format(d.ticket_price * (1 - d.discount))}
                </td>
                <td>
                  <button
                    type="button"
                    className="minus"
                    onClick={() => countClick("minus", d.ticket_id)}
                  >
                    -
                  </button>
                  <input
                    type="number"
                    className="numbox"
                    value={count[d.ticket_id] || 0}
                    onChange={countTicket}
                    readOnly
                  />
                  <input
                    type="hidden"
                    className="ticket-id"
                    value={d.ticket_id}
                  />
                  <button
                    type="button"
                    className="plus"
                    onClick={() => countClick("plus", d.ticket_id)}
                  >
                    +
                  </button>
                </td>
                <td className="total"></td>
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr className="totalsum">
              <td>총 가격 :</td>
              <td>
                <input
                  type="number"
                  className="mt-4 mb-4"
                  id="sum"
                  value={sum}
                  readOnly
                />
              </td>
              <td>포인트 사용 :</td>
              <td>
                <input
                  type="number"
                  className="mt-4 mb-4"
                  id="mypoint"
                  value={isDataLoaded ? mypoint : ""}
                  max={isDataLoaded ? data.mypoint[0]["sum_point"] : ""}
                  min="0"
                  onChange={handlePointChange}
                />
              </td>
              <td>
                <button
                  id="buy-btn"
                  type="button"
                  className="mt-4 mb-4"
                  style={{ float: "right" }}
                  onClick={handleBuyClick}
                >
                  구매 하기
                </button>
              </td>
            </tr>
          </tfoot>
        </table>
      </form>
    </div>
  );
};

export default Order;
