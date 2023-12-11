import styles from "./updateBoard.module.css";
import { Container } from "react-bootstrap";
import SelectType from "./component/selectType";
import { useEffect, useRef, useState } from "react";
import axios from "axios";
import Ckeditor from "../components/ckeditor";
import { useLocation } from "react-router-dom";
import ImageUpload from "./component/imageUpload";

function UpdateBoard() {
  const ckeditorData = useRef("");
  const [title, setTitle] = useState("");
  const [typeSelect, setTypeSelect] = useState("0");
  const [content, setContent] = useState("");
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [originBoardImg, setOriginBoardImg] = useState([]);
  const [ImageCheck, setImageCheck] = useState("");
  const [originMemberId, setOriginMemberId] = useState("");
  //주소에서 값가져오기
  const location = useLocation();
  const urlSearch = new URLSearchParams(location.search);
  const board_id = urlSearch.get("board_id");

  useEffect(() => {
    async function ready() {
      const detailData = await getDetailInfo();

      setTypeSelect(detailData.b_type);
      setTitle(detailData.b_title);
      setContent(detailData.b_content);
      setOriginBoardImg(detailData.boardImg);
      setOriginMemberId(detailData.member_id);
    }

    ready();
  }, []);

  const loginCheck = (originMemberId) => {
    const loginMember_id = sessionStorage.getItem("MEMBER_ID");
    const adminCheck = sessionStorage.getItem("ADMIN");
    const orignMember_id = originMemberId;
    if (loginMember_id !== orignMember_id && adminCheck === null) {
      window.alert("권한이 없거나 로그인 세션이 만료되었습니다");
      window.location.href = "/board";
    }
  };

  useEffect(() => {
    async function ready() {
      const detailData = await getDetailInfo();
      loginCheck(detailData.member_id);
      setOriginBoardImg(detailData.boardImg);
    }

    ready();
  }, [ImageCheck]);

  const handleValueChange = (slValue) => {
    typeSelect.current = slValue;
  };

  const getDetailInfo = async () => {
    const board_id = urlSearch.get("board_id");

    const response = await axios.get(
      "http://localhost:8080/board/updateBoard",
      {
        params: {
          board_id: board_id,
        },
      }
    );
    return response.data;
  };

  const fetchData = async () => {
    if (typeSelect.current === "0") window.alert("게시판 태그를 선택해주세요!");
    // else if (title.length <= 3)
    //     window.alert("제목을 3글자 이상 입력해주세요!");
    else if (ckeditorData.current.length <= 5)
      window.alert("본문은 5글자 이상 입력해주세요!");
    else {
      try {
        // 텍스트 데이터 전송
        await axios.post("http://localhost:8080/board/updateBoard", {
          b_title: title,
          b_type: typeSelect,
          b_content: ckeditorData.current,
          board_id: board_id,
        });

        if (selectedFiles.length > 0) {
          // 이미지 데이터 전송
          const formData = new FormData();

          // 이미지 파일 추가
          selectedFiles.forEach((file) => {
            formData.append("file", file);
          });

          // boardId와 함께 이미지 업로드 API에 전송
          await axios.post(
            `http://localhost:8080/board/imageUpload/${board_id}`,
            formData,
            {
              headers: {
                "Content-Type": "multipart/form-data",
              },
            }
          );
        }

        window.location.href = `/detail?board_id=${board_id}`;
      } catch (error) { }
    }
  };

  function cancle() {
    if (window.confirm("글 작성을 취소하시겠습니까?")) {
      window.location.href = `/detail?board_id=${urlSearch.get("board_id")}`;
    }
  }

  return (
    <div className={styles.create_board} id="create-board">
      <Container>
        <SelectType
          typeSelect={typeSelect}
          onValueChange={handleValueChange}
          b_type={typeSelect}
          setTypeSelect={setTypeSelect}
          b_title={title}
          setTitleValue={setTitle}
        />
        <hr />
        <Ckeditor
          ckeditorData={ckeditorData}
          setContent={setContent}
          content={content}
        />

        <ImageUpload
          selectedFiles={selectedFiles}
          setSelectedFiles={setSelectedFiles}
          originBoardImg={originBoardImg}
          setOriginBoardImg={setOriginBoardImg}
          board_id={board_id}
          setImageCheck={setImageCheck}
        />

        <br />

        <div id="insert_btn_wrap" className={styles.insert_btn_wrap}>
          <input
            type="button"
            id="cancle_btn"
            className="btn btn_blue"
            onClick={cancle}
            value="취소"
          />
          <input
            type="submit"
            className="btn btn_blue"
            id="submit"
            onClick={fetchData}
            value="확인"
          />
        </div>
      </Container>
    </div>
  );
}

export default UpdateBoard;
