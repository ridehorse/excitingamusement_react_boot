import React from "react";
import { Link } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";
import "jquery/dist/jquery.min.js";
import "bootstrap/dist/js/bootstrap.bundle.min.js";
import "./Promotion.css";
const PromotionCard = ({ promotion }) => {
  return (
    <div className="card">
      <img
        className="card-img-top"
        src={promotion.promotion_img}
        alt="Promotion Ride"
      />

      <div className="card-body">
        <h5 className="card-title">{promotion.promotion_content}</h5>
        <p className="card-text">{promotion.promotion_name}</p>
        <button className="btn btn-primary" type="button">
          <Link to={`/Promotionprice?promotion_id=${promotion.promotion_id}`}>
            보러 가기
          </Link>
        </button>
      </div>
    </div>
  );
};

export default PromotionCard;
