import { useRef, useState } from "react";
import CustomerMove from "../../customerMove";
import ImageUpload from "./component/imageUpload";
import SelectType from "./component/selectType";
import axios from "axios";


function InsertInquiry() {
  const typeSelect = useRef("예매문의");
  const [titleInputRef, setTitleInputRef] = useState("");
  const [b_content, setBContent] = useState('');
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [checked, setChecked] = useState(false);



  const BackToTheController = () => {

    // 임시로그인데이터
    const member_id = sessionStorage.getItem("MEMBER_ID");
    if (member_id === null) {
      window.alert("로그인해주세요!");


    } else if (b_content.length === 0) {
      window.alert("내용을 입력해주세요!");
    } else if (titleInputRef.length === 0) {
      window.alert("제목을 입력해주세요!");
    } else {


      axios
        .post("http://localhost:8080/customer/insertInquiry", {
          b_title: titleInputRef,
          b_type: typeSelect.current,
          b_content: b_content,
          member_id: member_id
        })
        .then((response) => {
          if (selectedFiles.length > 0) {
            // 이미지 데이터 전송
            const formData = new FormData();

            // 이미지 파일 추가
            selectedFiles.forEach((file) => {
              formData.append("file", file);
            });

            const inquiry_num = response.data;
            axios
              .post(
                `http://localhost:8080/customer/imageUpload?inquiry_num=${inquiry_num}`,
                formData,
                {
                  headers: {
                    "Content-Type": "multipart/form-data",
                  },
                }
              )
              .then(() => {
                window.location.href = "/inquiry";
              })
              .catch((error) => {
              });
          }
        })
        .catch((error) => {
        });
    }
  };

  // 글 주제
  const changeSelectValue = (event) => {
    typeSelect.current = event.target.value;
  };

  const handleTitleValueChange = (TitleValue) => {
    setTitleInputRef(TitleValue);
  };

  const handleBContentChange = (e) => {
    setBContent(e.target.value);
  };

  const handleCheck = () => {
    setChecked(!checked);
  };

  return (
    <>
      <div style={{ margin: '0 150px' }}>

      </div>
      <div id="create-board">
        <div className="container">
          <div className="create-window">
            <div style={{ textAlign: 'center', margin: '0 0 50px 0' }}>
              <h1>이용문의</h1>
            </div>

            <hr style={{ maxWidth: '800px' }} />

            <SelectType
              typeSelect={typeSelect}
              onValueChange={changeSelectValue}
              setTitleValue={handleTitleValueChange}
              setTitleInputRef={setTitleInputRef}
            />

            {/* top end */}

            <hr style={{ maxWidth: '800px' }} />

            <div className="mb-3">
              <textarea className="form-control" name="b_content" id="exampleFormControlTextarea1" rows="3" placeholder="" value={b_content} onChange={handleBContentChange}></textarea>
            </div>

            <ImageUpload
              selectedFiles={selectedFiles}
              setSelectedFiles={setSelectedFiles}
            />


            <table>
              <tbody>
                <tr style={{ height: '100px' }}>
                  <td style={{ width: '20%', fontStyle: 'bold', fontSize: 20 }}>개인정보 수집,이용동의서</td>
                </tr>
                <tr>
                  <td>
                    <textarea rows="10" cols="50" name="b_content" readOnly style={{ width: '100%', resize: 'none', margin: 'auto' }}>
                      개인 정보 수집, 이용 동의서

                      본인은 방문 전 이용문의 작성과 관련하여 귀사가 아래와 같이 본인의 개인정보를 수집, 이용하는데 동의합니다.

                      개인정보 수집, 이용에 관한 사항

                      1.개인정보의 수집, 이용 목적
                      고객의 요청ㆍ문의사항 확인, 사실조사를 위한 연락ㆍ통지, 처리결과 통보 등의 목적

                      2.수집하는 개인정보의 항목
                      ㆍ필수입력사항

                      이름, E-mail
                      ㆍ서비스 이용과정이나 사업처리 과정에서 아래와 같은 정보들이 생성되어 수집될 수 있습니다.

                      접속로그, 쿠키, 접속IP정보

                      3.개인정보의 보유, 이용기간
                      수집, 이용에 관한 동의일로부터 1년(이후에는 작성내용만 보관됩니다.)

                      ※ 귀하는 개인정보 수집, 이용에 대한 동의를 거부하실 권리가 있으며, 동의를 거부하실 경우 서비스 이용이 제한됩니다.</textarea>
                  </td>
                </tr>
              </tbody>
            </table>

            <div style={{ float: 'right', margin: '0 0 15px 0' }}>
              <input type="checkbox" name="check1" checked={checked} onChange={handleCheck} />&nbsp;개인정보 수집 및 이용에 동의합니다.
            </div>

            <div style={{ clear: 'both' }}></div>

            <div id="insert-btn-wrap">
              <input type="submit" className="btn btn-blue" id="submit" onClick={BackToTheController} value="확인" />
            </div>

          </div>
        </div>
      </div>
    </>
  );
}

export default InsertInquiry;