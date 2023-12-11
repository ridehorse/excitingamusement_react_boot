import styles from "./addBoard.module.css";
import { Container } from "react-bootstrap";
import SelectType from "./component/selectType";
import { useRef, useState } from "react";
import axios from "axios";
import Ckeditor from "../components/ckeditor";
import ImageUpload from "./component/imageUpload";

function AddBoard() {
  const typeSelect = useRef("0");
  const titleInputRef = useRef("");
  const ckeditorData = useRef("");
  const [content, setContent] = useState(undefined);
  const [selectedFiles, setSelectedFiles] = useState([]);


  const checkLogin = () => {
    const member_id = sessionStorage.getItem("MEMBER_ID");
    if (member_id === null) {
      window.alert("로그인해주세요!");
      return;
    } else {
      fetchData(member_id);
    }
  };


  const fetchData = async (member_id) => {
    if (typeSelect.current === "0") window.alert("게시판 태그를 선택해주세요!");
    else if (titleInputRef.current.length <= 3)
      window.alert("제목을 3글자 이상 입력해주세요!");
    else if (ckeditorData.current.length <= 5)
      window.alert("본문은 5글자 이상 입력해주세요!");
    else {
      try {
        // 텍스트 데이터 전송
        const response = await axios.post(
          "http://localhost:8080/board/addBoard",
          {
            b_title: titleInputRef.current,
            b_type: typeSelect.current,
            b_content: ckeditorData.current,
            member_id: member_id,
          }
        );

        const data = response.data;
        const boardId = data;

        if (selectedFiles.length > 0) {
          window.location.href = "/board";
        }
        // 이미지 데이터 전송
        const formData = new FormData();

        // 이미지 파일 추가
        selectedFiles.forEach((file) => {
          formData.append("file", file);
        });

        // boardId와 함께 이미지 업로드 API에 전송
        await axios
          .post(
            `http://localhost:8080/board/imageUpload/${boardId}`,
            formData,
            {
              headers: {
                "Content-Type": "multipart/form-data",
              },
            }
          )
          .then(() => {
            window.location.href = "/board";
          });
      } catch (error) { }
    }
  };

  function cancle() {
    if (window.confirm("글 작성을 취소하시겠습니까?")) {
      window.location.href = "/board";
    }
  }

  return (
    <div
      className={styles.board_create_board}
      id="create-board"
      style={{ marginTop: 75, marginBottom: 120 }}
    >
      <Container>
        <SelectType typeSelect={typeSelect} inputRef={titleInputRef} />
        <hr />
        <Ckeditor
          ckeditorData={ckeditorData}
          content={content}
          setContent={setContent}
        />

        <ImageUpload
          selectedFiles={selectedFiles}
          setSelectedFiles={setSelectedFiles}
        />

        <br />
        <div
          id={styles.insert_btn_wrap}
          className={[
            styles.insert_btn_wrap,
            styles[(styles.btn, styles.btn_blue)],
          ].join(" ")}
        >
          <input
            type="button"
            className={[styles.btn, styles.btn_blue].join(" ")}
            id={styles.cancle_btn}
            onClick={cancle}
            value="취소"
          />
          <input
            type="submit"
            className={[styles.btn, styles.btn_blue].join(" ")}
            id="submit"
            onClick={checkLogin}
            value="확인"
          />
        </div>
      </Container>
    </div>
  );
}

export default AddBoard;
