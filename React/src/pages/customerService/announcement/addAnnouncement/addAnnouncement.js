import axios from "axios";
import { useEffect, useRef, useState } from "react";
import { Container } from "react-bootstrap";
import styles from "./addAnnouncement.module.css";
import SelectType from "./component/selectType";

import Ckeditor from "../../components/ckeditor";
import ImageUpload from "./component/imageUpload";

function AddAnnouncement() {
  const titleInputRef = useRef("");
  const ckeditorData = useRef("");
  const [content, setContent] = useState(undefined);
  const [selectedFiles, setSelectedFiles] = useState([]);

  useEffect(() => {
    adminCheck();
  }, []);

  const handleTitleValueChange = (TitleValue) => {
    titleInputRef.current = TitleValue;
  };

  const adminCheck = () => {
    const adminCheck = sessionStorage.getItem("ADMIN");
    if (adminCheck === null) {
      window.alert("권한이 없습니다!!");
      window.location.href = "/";
    }
  };

  const fetchData = () => {
    if (titleInputRef.current.length <= 3) {
      window.alert("제목을 3글자 이상 입력해주세요!");
      return;
    }

    axios
      .post("http://localhost:8080/customer/insertAnnouncement", {
        c_title: titleInputRef.current,
        c_content: ckeditorData.current,
      })
      .then((response) => {
        const announcement_num = response.data;
        if (selectedFiles.length > 0) {
          // 이미지 데이터 전송
          const formData = new FormData();
          // 이미지 파일 추가
          selectedFiles.forEach((file) => {
            formData.append("file", file);
          });
          // boardId와 함께 이미지 업로드 API에 전송
          axios
            .post(
              `http://localhost:8080/customer/imageUpload?announcement_num=${announcement_num}`,
              formData,
              {
                headers: {
                  "Content-Type": "multipart/form-data",
                },
              }
            )
            .then(() => {
              window.location.href = "/announcement";
            })
            .catch((error) => { });
        } else {
          window.location.href = "/announcement";
        }
      });
  };

  function cancle() {
    if (window.confirm("글 작성을 취소하시겠습니까?")) {
      window.location.href = "/announcement";
    }
  }

  return (
    <>
      <section className="notice">
        <div className="create-Announcement" style={{ left: "200px" }}>
          <Container>
            <SelectType
              inputRef={titleInputRef}
              setTitleValue={handleTitleValueChange}
            />
            <hr />
            <Ckeditor
              ckeditorData={ckeditorData}
              //onImageUpload={handleImageUpload}
              content={content}
              setContent={setContent}
            />

            <div style={{ textAlign: "left", marginLeft: "200" }}>
              <ImageUpload
                selectedFiles={selectedFiles}
                setSelectedFiles={setSelectedFiles}
              />
            </div>

            <br />
            <div id="insert-btn-wrap">
              <input
                type="button"
                id="cancle-btn"
                className="btn btn-blue"
                onClick={cancle}
                value="취소"
              />
              <input
                type="submit"
                className="btn btn-blue"
                id="submit"
                onClick={fetchData}
                value="확인"
              />
            </div>
          </Container>
        </div>
      </section>
    </>
  );
}
export default AddAnnouncement;
