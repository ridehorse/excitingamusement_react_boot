import React, { useEffect } from 'react';
import 'bootstrap/dist/css/bootstrap.min.css';

function SelectType(props) {
  const { typeSelect, setTitleInputRef } = props;
  //const { titleValue, setTitleValue } = props;


  // useEffect(() => {
  // }, [titleValue]);

  const selectType = [
    { name: "예매문의", id: "option", value: "예매문의" },
    { name: "요금문의", id: "option", value: "요금문의" },
    { name: "제휴할인", id: "option", value: "제휴할인" },
    { name: "기타문의", id: "option", value: "기타문의" }
  ];

  const changeSelectValue = (event) => {
    typeSelect.current = event.target.value;
  };

  const changeTitleValue = (titleEvent) => {
    setTitleInputRef(titleEvent.target.value);

  };

  return (

    <>
      <div className="top-wrap">
        {/* 작성할 게시판 선택 */}
        <div className="select_wrap" style={{ width: '100%' }}>
          <select className='form-select'
            name='b_type'
            aria-label='Default select example'
            onChange={changeSelectValue}
          >
            {selectType.map((sl) => (
              <option
                key={sl.value}
                id={sl.id}
                value={sl.value}
              >
                {sl.name}
              </option>
            ))}
          </select><br />
        </div>

        <div className="form-floating mb-3">
          <input
            type="text"
            className="form-control"
            id="flootingInput"
            name="b_title"
            onChange={changeTitleValue} />
          <label htmlFor="flootingInput">제목</label>
        </div>
      </div>
    </>
  );
}

export default SelectType;