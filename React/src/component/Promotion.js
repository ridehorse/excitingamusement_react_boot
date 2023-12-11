import React, { useEffect, useState } from "react";
import PromotionCard from "./PromotionCard";
import axios from "axios";
import "./Promotion.css";
import "bootstrap/dist/css/bootstrap.min.css";
import "bootstrap-icons/font/bootstrap-icons.css";
import "jquery/dist/jquery.min.js";
import "bootstrap/dist/js/bootstrap.bundle.min.js";

function Promotion() {
  const [promotions, setPromotions] = useState([]);

  useEffect(() => {
    // 데이터를 가져오는 함수를 호출합니다.
    fetchPromotions();
  }, []);

  const fetchPromotions = async () => {
    try {
      const response = await axios.get("http://localhost:8080/promotion");
      console.log(response.data);
      setPromotions(response.data);
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div className="container">
      <header align="center">
        <h1>익사이팅과 함께 진행하는 프로모션들!</h1>
        <p>
          익사이팅에 찾아주셔서 감사합니다! 저희는 세계 각국의 놀이공원과
          프로모션을 진행하고 있습니다! 천천히 둘러보세요!
        </p>
      </header>
      <main className="container custom-main-padding border-bottom">
        <div className="container">
          <div className="card-deck">
            {promotions.map((promotion) => (
              <PromotionCard
                key={promotion.promotion_id}
                promotion={promotion}
              />
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}

export default Promotion;
