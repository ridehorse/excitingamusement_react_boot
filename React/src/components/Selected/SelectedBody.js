import React, { useEffect, useState } from "react";
import axios from "axios";
import SelectedItem from "./SelectedItem";
import ToastNotification from "../ToastNotification";

const SelectedBody = () => {
  const [selectedData, setSelectedData] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loadMoreVisible, setLoadMoreVisible] = useState(false);
  const member_id = sessionStorage.getItem("member_id");
  const [toast, setToast] = useState({ show: false, message: "", type: "" });

  const handleShowToast = (message, type) => {
    setToast({ show: true, message, type });
    setTimeout(() => {
      setToast({ show: false, message: "", type });
    }, 1200);
  };

  const fetchInitialData = async () => {
    try {
      const response = await axios.get(
        "http://localhost:8080/selectedapi/selectedlist",
        {
          params: {
            member_id,
          },
        }
      );
      setSelectedData(response.data);

      if (response.data.length) {
        setSelectedId(response.data[response.data.length - 1].selected_id);
      }
    } catch (error) {
      console.error("Error:", error);
    }
  };

  const fetchMoreData = async (selected_id = null) => {
    try {
      const response = await axios.post(
        "http://localhost:8080/selectedapi/selectedlist",
        {
          selected_id: selectedId,
          member_id,
        }
      );
      setSelectedData((prevData) => [...prevData, ...response.data]);

      if (response.data.length) {
        setSelectedId(response.data[response.data.length - 1].selected_id);
      }
    } catch (error) {
      console.error("Error:", error);
    }
  };

  const fetchCount = async (selected_id = null) => {
    try {
      const response = await axios.post(
        "http://localhost:8080/selectedapi/selectedcount",
        {
          member_id,
          selected_id: selectedId,
        }
      );
      setLoadMoreVisible(response.data > 6);
    } catch (error) {
      console.error("Error:", error);
    }
  };

  useEffect(() => {
    fetchInitialData();
    fetchCount();
  }, []);

  const loadMore = () => {
    fetchMoreData(selectedId);
    fetchCount(selectedId);
  };

  return (
    <article className="offset-1 col-8">
      <h2>위시리스트</h2>
      <div className="row gx-4 gx-lg-5 row-cols-1 row-cols-md-2 row-cols-xl-3 py-4">
        {selectedData &&
          selectedData.map((data, index) => (
            <SelectedItem
              key={index}
              data={data}
              member_id={member_id}
              handleShowToast={handleShowToast}
            />
          ))}
      </div>
      {loadMoreVisible && (
        <div className="text-center">
          <button
            type="button"
            id="add-list-btn"
            className="btn btn-light"
            onClick={loadMore}
          >
            더보기
          </button>
        </div>
      )}
      <ToastNotification toast={toast} />
    </article>
  );
};

export default SelectedBody;
