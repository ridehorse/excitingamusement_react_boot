import 'bootstrap/dist/css/bootstrap.min.css';
import React from 'react';
import styles from '../addBoard.module.css'

function SelectType(props) {
    const { typeSelect, inputRef } = props;

    const selectType = [
        { name: "선택", id: "option", value: "0" },
        { name: "국내", id: "option", value: "국내" },
        { name: "해외", id: "option", value: "해외" },
        { name: "질문", id: "option", value: "질문" },
        { name: "자유", id: "option", value: "자유" }

    ];

    const changeSelectValue = (event) => {
        typeSelect.current = event.target.value;
    };

    const changeTitleValue = (titleEvent) => {
        inputRef.current = titleEvent.target.value;
    };

    return (
        <div>
            <div className={styles.board_create_window}>
                <div className={styles.top_wrap}>
                    <select
                        className={`${styles.form_select} form-select`}
                        name='b_type'
                        aria-label='Default select example'
                        onChange={changeSelectValue}
                        value={typeSelect.currnt}
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
                    </select>
                    <br />
                </div>
                <div className={`form-floating mb-3 ${styles.form_floating}`}>
                    <input
                        type="text"
                        className={`form-control ${styles.form_control}`}
                        id="floatingInput"
                        name="b_title"
                        onChange={changeTitleValue}
                    />
                    <label htmlFor="floatingInput">제목</label>
                </div>
            </div>
        </div>
    );
}

export default SelectType;