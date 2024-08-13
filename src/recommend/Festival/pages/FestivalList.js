import React from 'react';
import { Helmet } from 'react-helmet-async';
import { useTranslation } from 'react-i18next';
import { OuterBox } from '../../../commons/components/LayoutBox';
import { MainTitle } from '../../../commons/components/TitleBox';
import ListContainer from '../containers/ListContainer';

const FestivalList = () => {
  const { t } = useTranslation();

  return (
    <>
      <Helmet>
        <title>{t('축제_목록')}</title>
      </Helmet>
      <OuterBox>
        <MainTitle>{t('축제_목록')}</MainTitle>
        <ListContainer />
      </OuterBox>
    </>
  );
};

export default React.memo(FestivalList);
