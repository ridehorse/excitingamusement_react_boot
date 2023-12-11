import axios from "axios";
import React, { useEffect, useState } from "react";
import { Col, Card } from "react-bootstrap";
import { BsHeart, BsHeartFill } from "react-icons/bs";

const SelectedItem = ({ data, member_id, handleShowToast }) => {
  const [isFavorite, setIsFavorite] = useState(false);
  const [animateHeart, setAnimateHeart] = useState(false);

  useEffect(() => {
    if (!member_id) return;
    axios
      .post("http://localhost:8080/selectedapi/check", {
        amuse_id: data.amuse_id,
        member_id: member_id,
      })
      .then((response) => {
        setIsFavorite(response.data.check === 1);
        console.log(response.data.check);
      })
      .catch((error) => {
        console.error(error);
      });
  }, [data.amuse_id, member_id]);

  const handleHeartClick = () => {
    if (!member_id) {
      window.location.href = "/login";
      return;
    }

    if (animateHeart) return;
    setAnimateHeart(true);

    axios
      .post("http://localhost:8080/selectedapi/insertDelete", {
        amuse_id: data.amuse_id,
        member_id,
      })
      .then((response) => {
        setTimeout(() => {
          setIsFavorite(response.data.check === 1);
          setAnimateHeart(false);
          console.log(response.data.check);
          // 토스트 알림 처리
          if (response.data.check === 1) {
            handleShowToast("위시리스트에 추가되었어요", "success");
          } else {
            handleShowToast("위시리스트에서 제외되었어요", "failed");
          }
        }, 1000);
      })
      .catch((error) => {
        console.error(error);
      });
  };

  return (
    <Col className="mb-5">
      <Card className="h-100">
        <div className="position-relative overflow-hidden">
          <div
            className={`animate__animated position-absolute ${
              animateHeart ? "animate__bounce" : ""
            }`}
            onClick={handleHeartClick}
            style={{ width: "35px", top: "10px", right: "10px", zIndex: "100" }}
          >
            {isFavorite ? (
              <BsHeartFill
                className="custom-icon"
                style={{ fontSize: "2rem", color: "red" }}
              />
            ) : (
              <BsHeart
                className="custom-icon"
                style={{ fontSize: "2rem", color: "red" }}
              />
            )}
          </div>
          <Card.Link href={`/amuseDetail?amuse_id=${data.amuse_id}`}>
            <Card.Img
              className="custom-card-img"
              src={data.url}
              alt={data.a_name}
            />
          </Card.Link>
        </div>
        <Card.Body className="p-4">
          <Card.Text className="text-center mb-0">{data.a_name}</Card.Text>
        </Card.Body>
      </Card>
    </Col>
  );
};

export default SelectedItem;
