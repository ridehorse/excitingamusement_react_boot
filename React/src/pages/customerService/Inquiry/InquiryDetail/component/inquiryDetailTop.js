import styles from "../inquiryDetail.module.css";

function InquiryDetailTop(viewData) {
  return (
    <>
      <div className={styles.header_inner}>
        <p style={{ fontSize: "20px", float: "left" }}>
          <b>{viewData[0] && viewData[0].b_title}</b>
        </p>
        <div className={styles.heder_inner_inner} style={{ clear: "both" }}>
          <br />
          <span
            style={{
              marginBottom: "10px",
              fontSize: "15px",
            }}
          >
            <a
              href={
                viewData[0]
                  ? `/inquiry?member_id=${viewData[0].member_id}`
                  : "#"
              }
            >
              {viewData[0] && viewData[0].member_id}
            </a>
          </span>
          <span style={{ float: "right" }}>
            {viewData[0] && viewData[0].postdate}
          </span>
        </div>
      </div>
    </>
  );
}

export default InquiryDetailTop;
