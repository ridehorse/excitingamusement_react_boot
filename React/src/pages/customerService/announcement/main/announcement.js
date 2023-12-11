import { useEffect, useState } from "react";
import React from "react";

import styles from "./announcement.module.css";
import AnnouncementList from "./component/announcementList";

function Announcement() {
  return (
    <>
      <section className={styles.notice}>
        <div className={styles.anno_list}>
          <div className={styles.page_title} style={{ marginRight: 100 }}>
            <h1>공지사항</h1>
          </div>
          <br />
          <div className={styles.anno_container}>
            <AnnouncementList />
          </div>
        </div>
      </section>
    </>
  );
}

export default Announcement;
