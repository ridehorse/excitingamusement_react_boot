import axios from "axios";
import { useEffect, useState } from "react";
import styles from "../inquiryDetail.module.css";
function ImgWrap({ inquiry_num }) {
  const [imageData, setImageData] = useState([]);

  useEffect(() => {
    getImg();
  }, []);

  const getImg = async () => {
    await axios
      .get("http://localhost:8080/customer/inquiryImage", {
        params: {
          inquiry_num: inquiry_num,
        },
      })
      .then((response) => {
        setImageData(response.data.data);
      })
      .catch((error) => {
      });
  };

  return (
    <>
      <div className={styles.image_inner_wrap}>
        {imageData &&
          imageData.map((img, index) => (
            <a href={img.boardimg} key={index}>
              <img src={img.boardimg} alt="1" style={{ width: "200px" }}></img>
            </a>
          ))}
      </div>
    </>
  );
}
export default ImgWrap;
