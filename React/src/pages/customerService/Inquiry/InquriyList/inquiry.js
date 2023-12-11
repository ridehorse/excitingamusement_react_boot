import { useEffect, useState } from "react";
import React from "react";

import styles from "./inquiry.module.css";
import InquiryList from "./component/inquiryList";

function Inquiry() {
  return (
    <div>
      <section className={styles.notice}>
        <div
          className={styles.board_list}
          style={{ marginLeft: 250 }}
        >
          <div className={styles.page_title} style={{ marginRight: 150 }}>
            <h1>문의내역</h1>
          </div>
          <br></br>
          <div className={styles.container}>
            <InquiryList></InquiryList>
          </div>
        </div>
      </section>
    </div>
  );
}

export default Inquiry;
